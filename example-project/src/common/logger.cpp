// ─────────────────────────────────────────────────────────────────────────────
// Аудит-журнал с криптографической хэш-цепочкой (Стрибог-256)
//
// Каждая аудит-запись содержит:
//   1. Порядковый номер
//   2. Временную метку ISO 8601
//   3. Тип события, субъект, объект, действие, результат
//   4. Стрибог-256 хэш предыдущей записи (H_{i-1})
//   5. Стрибог-256 хэш текущей записи: H_i = Стрибог-256(запись_i || H_{i-1})
//
// Такая структура образует append-only цепочку, в которой подделка
// любой прошлой записи нарушает все последующие хэши.
// ─────────────────────────────────────────────────────────────────────────────
#include "common/logger.hpp"
#include "crypto/streebog.hpp"
#include "common/utils.hpp"
#include <fstream>
#include <iostream>
#include <mutex>
#include <sstream>
#include <iomanip>
#include <ctime>

namespace gost { namespace common {

struct Logger::Impl {
    std::string log_file_path;
    std::ofstream log_file;
    LogLevel min_level = LogLevel::INFO;
    bool audit_chain = true;
    std::string chain_tip;       // Стрибог-256 последней аудит-записи (hex)
    uint64_t audit_seq = 0;
    std::mutex mu;

    // Инициализируем нулевой хэш цепочки: Стрибог-256("GENESIS")
    Impl() {
        static const uint8_t genesis[] = "GENESIS-ГОСТ-АУДИТ-ЦЕПОЧКА";
        auto h = streebog256(genesis, sizeof(genesis) - 1);
        chain_tip = utils::to_hex(h.data(), h.size());
    }
};

Logger& Logger::instance() {
    static Logger inst;
    return inst;
}

Logger::Logger() : impl_(new Impl()) {}
Logger::~Logger() { delete impl_; }

void Logger::set_log_file(const std::string& path) {
    std::lock_guard<std::mutex> lock(impl_->mu);
    impl_->log_file_path = path;
    impl_->log_file.open(path, std::ios::app);
}

void Logger::set_level(LogLevel level) {
    impl_->min_level = level;
}

void Logger::enable_audit_chain(bool enable) {
    impl_->audit_chain = enable;
}

static const char* level_name(LogLevel l) {
    switch (l) {
        case LogLevel::DEBUG:    return "DEBUG";
        case LogLevel::INFO:     return "INFO";
        case LogLevel::WARN:     return "WARN";
        case LogLevel::ERROR:    return "ERROR";
        case LogLevel::CRITICAL: return "CRITICAL";
        case LogLevel::AUDIT:    return "AUDIT";
        default: return "?";
    }
}

void Logger::log(LogLevel level, const std::string& module, const std::string& message) {
    if (level != LogLevel::AUDIT && level < impl_->min_level) return;

    std::lock_guard<std::mutex> lock(impl_->mu);

    std::string ts = utils::current_timestamp();
    std::ostringstream line;
    line << "[" << ts << "] [" << level_name(level) << "] [" << module << "] " << message;
    std::string entry = line.str();

    // Вывод в stdout
    std::cout << entry << "\n";

    // Вывод в файл
    if (impl_->log_file.is_open()) {
        impl_->log_file << entry << "\n";
        impl_->log_file.flush();
    }
}

void Logger::debug(const std::string& module, const std::string& msg) {
    log(LogLevel::DEBUG, module, msg);
}
void Logger::info(const std::string& module, const std::string& msg) {
    log(LogLevel::INFO, module, msg);
}
void Logger::warn(const std::string& module, const std::string& msg) {
    log(LogLevel::WARN, module, msg);
}
void Logger::error(const std::string& module, const std::string& msg) {
    log(LogLevel::ERROR, module, msg);
}

void Logger::audit(const std::string& event_type,
                   const std::string& subject,
                   const std::string& object,
                   const std::string& action,
                   bool success,
                   const std::string& details)
{
    std::lock_guard<std::mutex> lock(impl_->mu);

    std::string ts = utils::current_timestamp();
    uint64_t seq = ++impl_->audit_seq;

    // Строим тело аудит-записи (детерминировано)
    std::ostringstream body;
    body << "SEQ=" << seq
         << " TS=" << ts
         << " EVENT=" << event_type
         << " SUBJ=" << subject
         << " OBJ=" << object
         << " ACTION=" << action
         << " RESULT=" << (success ? "OK" : "FAIL")
         << " PREV=" << impl_->chain_tip;
    if (!details.empty()) body << " DETAILS=" << details;
    std::string body_str = body.str();

    // Обновляем хэш-цепочку: H_i = Стрибог-256(body || H_{i-1})
    std::string chain_input = body_str + "|" + impl_->chain_tip;
    auto h = streebog256(
        reinterpret_cast<const uint8_t*>(chain_input.data()), chain_input.size());
    impl_->chain_tip = utils::to_hex(h.data(), h.size());

    std::ostringstream line;
    line << "[" << ts << "] [AUDIT] " << body_str << " HASH=" << impl_->chain_tip;
    std::string entry = line.str();

    std::cout << entry << "\n";
    if (impl_->log_file.is_open()) {
        impl_->log_file << entry << "\n";
        impl_->log_file.flush();
    }
}

std::string Logger::chain_tip_hash() const {
    return impl_->chain_tip;
}

// Перечитывает файл и проверяет HASH поле каждой AUDIT-записи
bool Logger::verify_audit_chain(const std::string& log_file) {
    std::ifstream f(log_file);
    if (!f.is_open()) return false;

    // Начальный хэш — тот же genesis
    static const uint8_t genesis[] = "GENESIS-ГОСТ-АУДИТ-ЦЕПОЧКА";
    auto h = streebog256(genesis, sizeof(genesis) - 1);
    std::string prev_hash = utils::to_hex(h.data(), h.size());

    std::string line;
    uint64_t seq = 0;
    bool ok = true;

    while (std::getline(f, line)) {
        if (line.find("[AUDIT]") == std::string::npos) continue;

        // Извлекаем HASH= в конце строки
        auto hash_pos = line.rfind(" HASH=");
        if (hash_pos == std::string::npos) { ok = false; break; }
        std::string stored_hash = line.substr(hash_pos + 6);

        // Восстанавливаем тело записи (без HASH= в конце)
        std::string body_part = line.substr(line.find("[AUDIT] ") + 8, hash_pos - line.find("[AUDIT] ") - 8);

        // body содержит PREV= — он уже встроен
        std::string chain_input = body_part + "|" + prev_hash;
        auto expected_h = streebog256(
            reinterpret_cast<const uint8_t*>(chain_input.data()), chain_input.size());
        std::string expected_hash = utils::to_hex(expected_h.data(), expected_h.size());

        if (expected_hash != stored_hash) {
            std::cerr << "Нарушена целостность аудит-цепочки на записи " << ++seq << "\n";
            ok = false;
            break;
        }
        prev_hash = stored_hash;
        ++seq;
    }

    if (ok)
        std::cout << "Аудит-цепочка Стрибог-256 проверена успешно (" << seq << " записей)\n";
    return ok;
}

}} // namespace gost::common