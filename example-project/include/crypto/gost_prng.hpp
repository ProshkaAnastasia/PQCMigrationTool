#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// ГПСЧ — генератор псевдослучайных чисел по ГОСТ Р 34.20-2012
// Реализация: CTR_DRBG на основе шифра Кузнечик (Grasshopper)
//
// Стандарты:
//   ГОСТ Р 34.20-2012  — требования к ГПСЧ
//   Р 1323565.1.006-2017 — рекомендации по генерации ключей
//   NIST SP 800-90A Rev.1 — CTR_DRBG (аналог для сравнения)
//
// Конструкция: CTR_DRBG с Кузнечик (Kuznechik/Grasshopper)
//   Длина блока: 128 бит, Длина ключа: 256 бит
//   Длина seed: 384 бит (внутреннее состояние)
//   Максимальный запрос: 2^16 байт
//   Интервал пересева: 2^48 запросов
//
// Безопасность: постквантово стойкий (симметричная операция)
// ─────────────────────────────────────────────────────────────────────────────
#include <cstdint>
#include <vector>
#include <array>

namespace gost {

class GostPrng {
public:
    // Инициализация из системного источника энтропии (/dev/urandom)
    GostPrng();

    // Инициализация из явного seed (для детерминированных тестов)
    explicit GostPrng(const std::vector<uint8_t>& seed);

    ~GostPrng();
    GostPrng(const GostPrng&) = delete;
    GostPrng& operator=(const GostPrng&) = delete;

    // Генерация случайных байт
    std::vector<uint8_t> generate(size_t num_bytes);
    void generate(uint8_t* buf, size_t num_bytes);

    // Пересев (reseed) из дополнительного источника энтропии
    void reseed(const std::vector<uint8_t>& additional_input = {});

    // Генерация ключа для Кузнечик (256 бит = 32 байта)
    std::array<uint8_t, 32> generate_grasshopper_key();

    // Генерация IV/Nonce (128 бит = 16 байт)
    std::array<uint8_t, 16> generate_iv();

    // Генерация 8-байтового IV для режима CTR
    std::array<uint8_t, 8> generate_ctr_iv();

    // Количество запросов с момента последнего пересева
    uint64_t requests_since_reseed() const;

private:
    struct Impl;
    Impl* impl_;
};

// Глобальный ГПСЧ (singleton, поточно-безопасный)
GostPrng& global_prng();

// Генерация случайных байт через глобальный ГПСЧ
std::vector<uint8_t> random_bytes(size_t n);
uint32_t random_uint32();
uint64_t random_uint64();

} // namespace gost