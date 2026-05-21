// ─────────────────────────────────────────────────────────────────────────────
// Вспомогательные утилиты: кодирование, случайные данные, I/O
// ─────────────────────────────────────────────────────────────────────────────
#include "common/utils.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <cstring>
#include <ctime>
#include <cassert>
#include <random>

// /dev/urandom для CSPRNG
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

namespace gost { namespace utils {

// ── Hex ──────────────────────────────────────────────────────────────────────

std::string to_hex(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i)
        oss << std::setw(2) << (unsigned)data[i];
    return oss.str();
}

std::string to_hex(const std::vector<uint8_t>& data) {
    return to_hex(data.data(), data.size());
}

std::vector<uint8_t> from_hex(const std::string& hex) {
    if (hex.size() % 2 != 0)
        throw std::invalid_argument("from_hex: нечётная длина строки");
    std::vector<uint8_t> out(hex.size() / 2);
    for (size_t i = 0; i < out.size(); ++i) {
        auto c = [](char h) -> uint8_t {
            if (h >= '0' && h <= '9') return h - '0';
            if (h >= 'a' && h <= 'f') return 10 + h - 'a';
            if (h >= 'A' && h <= 'F') return 10 + h - 'A';
            throw std::invalid_argument("from_hex: неверный символ");
        };
        out[i] = (c(hex[2*i]) << 4) | c(hex[2*i+1]);
    }
    return out;
}

// ── Base64 ───────────────────────────────────────────────────────────────────

static const char B64_CHARS[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string to_base64(const uint8_t* data, size_t len) {
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    for (size_t i = 0; i < len; i += 3) {
        uint32_t b = (uint32_t)data[i] << 16;
        if (i + 1 < len) b |= (uint32_t)data[i+1] << 8;
        if (i + 2 < len) b |= (uint32_t)data[i+2];
        out += B64_CHARS[(b >> 18) & 0x3F];
        out += B64_CHARS[(b >> 12) & 0x3F];
        out += (i + 1 < len) ? B64_CHARS[(b >> 6) & 0x3F] : '=';
        out += (i + 2 < len) ? B64_CHARS[b & 0x3F] : '=';
    }
    return out;
}

std::string to_base64(const std::vector<uint8_t>& data) {
    return to_base64(data.data(), data.size());
}

std::vector<uint8_t> from_base64(const std::string& b64) {
    static const int8_t DEC[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
    };

    std::vector<uint8_t> out;
    out.reserve((b64.size() / 4) * 3);

    for (size_t i = 0; i + 3 < b64.size(); i += 4) {
        uint32_t b = ((uint32_t)DEC[(uint8_t)b64[i]]   << 18)
                   | ((uint32_t)DEC[(uint8_t)b64[i+1]] << 12)
                   | ((uint32_t)DEC[(uint8_t)b64[i+2]] <<  6)
                   | ((uint32_t)DEC[(uint8_t)b64[i+3]]);
        out.push_back((b >> 16) & 0xFF);
        if (b64[i+2] != '=') out.push_back((b >> 8) & 0xFF);
        if (b64[i+3] != '=') out.push_back(b & 0xFF);
    }
    return out;
}

// ── Случайные данные (/dev/urandom) ──────────────────────────────────────────

std::vector<uint8_t> secure_random(size_t n) {
    std::vector<uint8_t> buf(n);
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) throw std::runtime_error("Не удалось открыть /dev/urandom");
    ssize_t got = 0;
    while ((size_t)got < n) {
        ssize_t r = read(fd, buf.data() + got, n - got);
        if (r <= 0) { close(fd); throw std::runtime_error("/dev/urandom: ошибка чтения"); }
        got += r;
    }
    close(fd);
    return buf;
}

std::string secure_random_hex(size_t bytes) {
    return to_hex(secure_random(bytes));
}

// ── Безопасное обнуление памяти ───────────────────────────────────────────────

void secure_zero(void* ptr, size_t len) {
    volatile uint8_t* p = reinterpret_cast<volatile uint8_t*>(ptr);
    for (size_t i = 0; i < len; ++i) p[i] = 0;
}

void secure_zero(std::vector<uint8_t>& data) {
    secure_zero(data.data(), data.size());
    data.clear();
}

// ── Работа с файлами ──────────────────────────────────────────────────────────

std::vector<uint8_t> read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("Не удалось открыть файл: " + path);
    return std::vector<uint8_t>(
        std::istreambuf_iterator<char>(f),
        std::istreambuf_iterator<char>());
}

void write_file(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) throw std::runtime_error("Не удалось записать файл: " + path);
    f.write(reinterpret_cast<const char*>(data.data()), data.size());
}

bool file_exists(const std::string& path) {
    struct stat st;
    return stat(path.c_str(), &st) == 0;
}

size_t file_size(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) return 0;
    return (size_t)st.st_size;
}

// ── Временные метки ───────────────────────────────────────────────────────────

std::string current_timestamp() {
    return format_time(std::time(nullptr));
}

std::string format_time(std::time_t t) {
    char buf[32];
    struct tm* tm_info = gmtime(&t);
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", tm_info);
    return std::string(buf);
}

// ── Константное время сравнение ───────────────────────────────────────────────

bool constant_time_compare(const std::vector<uint8_t>& a,
                            const std::vector<uint8_t>& b) {
    if (a.size() != b.size()) return false;
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < a.size(); ++i)
        diff |= a[i] ^ b[i];
    return diff == 0;
}

// ── UUID генерация (версия 4, RFC 4122) ───────────────────────────────────────

std::string generate_uuid() {
    auto rand_bytes = secure_random(16);
    // Устанавливаем биты версии 4 и варианта
    rand_bytes[6] = (rand_bytes[6] & 0x0F) | 0x40;
    rand_bytes[8] = (rand_bytes[8] & 0x3F) | 0x80;

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (int i = 0; i < 16; ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) oss << '-';
        oss << std::setw(2) << (unsigned)rand_bytes[i];
    }
    return oss.str();
}

}} // namespace gost::utils