#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// Аудит-журнал с ГОСТ хэш-цепочкой (append-only log)
// Каждая запись содержит Стрибог-256 хэш предыдущей записи —
// образует криптографическую цепочку (blockchain-like structure)
// ─────────────────────────────────────────────────────────────────────────────
#include <string>
#include <cstdint>
#include <ctime>

namespace gost { namespace common {

enum class LogLevel { DEBUG, INFO, WARN, ERROR, CRITICAL, AUDIT };

class Logger {
public:
    static Logger& instance();

    void set_log_file(const std::string& path);
    void set_level(LogLevel min_level);
    void enable_audit_chain(bool enable);  // Хэш-цепочка Стрибог-256

    void log(LogLevel level, const std::string& module, const std::string& message);
    void debug(const std::string& module, const std::string& msg);
    void info(const std::string& module, const std::string& msg);
    void warn(const std::string& module, const std::string& msg);
    void error(const std::string& module, const std::string& msg);

    // Аудит-событие (всегда записывается, игнорирует уровень фильтрации)
    // Включает Стрибог-256 хэш предыдущей записи
    void audit(const std::string& event_type,
               const std::string& subject,
               const std::string& object,
               const std::string& action,
               bool success,
               const std::string& details = "");

    // Верификация целостности аудит-журнала (проверка хэш-цепочки)
    bool verify_audit_chain(const std::string& log_file);

    // Текущий хэш вершины цепочки (Стрибог-256)
    std::string chain_tip_hash() const;

private:
    Logger();
    ~Logger();
    struct Impl;
    Impl* impl_;
};

// Удобные макросы
#define LOG_DEBUG(mod, msg) ::gost::common::Logger::instance().debug(mod, msg)
#define LOG_INFO(mod, msg)  ::gost::common::Logger::instance().info(mod, msg)
#define LOG_WARN(mod, msg)  ::gost::common::Logger::instance().warn(mod, msg)
#define LOG_ERROR(mod, msg) ::gost::common::Logger::instance().error(mod, msg)
#define LOG_AUDIT(type, subj, obj, act, ok, ...) \
    ::gost::common::Logger::instance().audit(type, subj, obj, act, ok, ##__VA_ARGS__)

}} // namespace gost::common