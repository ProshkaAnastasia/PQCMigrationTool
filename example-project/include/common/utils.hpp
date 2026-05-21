#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// Утилиты: кодирование, случайные данные, работа с файлами
// ─────────────────────────────────────────────────────────────────────────────
#include <string>
#include <vector>
#include <cstdint>

namespace gost { namespace utils {

// Кодирование байт
std::string to_hex(const uint8_t* data, size_t len);
std::string to_hex(const std::vector<uint8_t>& data);
std::vector<uint8_t> from_hex(const std::string& hex);

std::string to_base64(const uint8_t* data, size_t len);
std::string to_base64(const std::vector<uint8_t>& data);
std::vector<uint8_t> from_base64(const std::string& b64);

// Случайные данные из /dev/urandom (для nonce, salt, challenge)
std::vector<uint8_t> secure_random(size_t n);
std::string secure_random_hex(size_t bytes);

// Безопасное обнуление памяти (защита от оптимизации компилятором)
void secure_zero(void* ptr, size_t len);
void secure_zero(std::vector<uint8_t>& data);

// Работа с файлами
std::vector<uint8_t> read_file(const std::string& path);
void write_file(const std::string& path, const std::vector<uint8_t>& data);
bool file_exists(const std::string& path);
size_t file_size(const std::string& path);

// Временные метки
std::string current_timestamp();          // ISO 8601
std::string format_time(std::time_t t);

// Константное время сравнение (защита от timing-атак)
bool constant_time_compare(const std::vector<uint8_t>& a,
                            const std::vector<uint8_t>& b);

// UUID генерация
std::string generate_uuid();

}} // namespace gost::utils