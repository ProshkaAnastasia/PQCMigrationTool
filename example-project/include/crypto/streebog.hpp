#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// Streebog — хэш-функция ГОСТ Р 34.11-2012 (Стрибог)
// Реализация через libgcrypt (GCRY_MD_STRIBOG256 / GCRY_MD_STRIBOG512)
//
// Стандарты:
//   ГОСТ Р 34.11-2012   — основной стандарт
//   RFC 6986             — интернациональное описание алгоритма
//   TC26 R 50.1.115-2016 — рекомендации по применению
//
// Постквантовый статус: СТОЙКИЙ (хэш-функции устойчивы к квантовым атакам
//   при длине вывода ≥ 256 бит; атака Гровера снижает безопасность вдвое,
//   но Стрибог-512 сохраняет 256-битную квантовую стойкость).
//
// Рекомендации ТК 26: Стрибог является предпочтительной хэш-функцией
//   для новых систем, заменяет ГОСТ Р 34.11-94.
// ─────────────────────────────────────────────────────────────────────────────
#include <cstdint>
#include <string>
#include <vector>
#include <array>

namespace gost {

// Длины выводов (в байтах)
constexpr size_t STREEBOG256_DIGEST_SIZE = 32;   // ГОСТ Р 34.11-2012 (256 бит)
constexpr size_t STREEBOG512_DIGEST_SIZE = 64;   // ГОСТ Р 34.11-2012 (512 бит)
constexpr size_t STREEBOG_BLOCK_SIZE     = 64;   // Блок 512 бит

using Digest256 = std::array<uint8_t, STREEBOG256_DIGEST_SIZE>;
using Digest512 = std::array<uint8_t, STREEBOG512_DIGEST_SIZE>;

// Стрибог-256 (ГОСТ Р 34.11-2012, выход 256 бит)
Digest256 streebog256(const uint8_t* data, size_t len);
Digest256 streebog256(const std::vector<uint8_t>& data);
Digest256 streebog256(const std::string& data);

// Стрибог-512 (ГОСТ Р 34.11-2012, выход 512 бит)
Digest512 streebog512(const uint8_t* data, size_t len);
Digest512 streebog512(const std::vector<uint8_t>& data);
Digest512 streebog512(const std::string& data);

// Потоковый интерфейс для обработки больших данных
class Streebog256Context {
public:
    Streebog256Context();
    ~Streebog256Context();
    Streebog256Context(const Streebog256Context&) = delete;
    Streebog256Context& operator=(const Streebog256Context&) = delete;

    void update(const uint8_t* data, size_t len);
    void update(const std::vector<uint8_t>& data);
    Digest256 finalize();

private:
    struct Impl;
    Impl* impl_;
};

class Streebog512Context {
public:
    Streebog512Context();
    ~Streebog512Context();
    Streebog512Context(const Streebog512Context&) = delete;
    Streebog512Context& operator=(const Streebog512Context&) = delete;

    void update(const uint8_t* data, size_t len);
    void update(const std::vector<uint8_t>& data);
    Digest512 finalize();

private:
    struct Impl;
    Impl* impl_;
};

// Вспомогательная функция — ГОСТ Р 34.11-94 (устаревший, для совместимости)
// ВНИМАНИЕ: Данный алгоритм квантово-уязвим и не рекомендуется для новых систем.
// Статус ТК 26: подлежит замене на Стрибог.
std::vector<uint8_t> gostr3411_94(const uint8_t* data, size_t len,
                                   const std::string& paramset = "CryptoPro-A");

} // namespace gost