#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// HMAC-Стрибог — код аутентификации сообщения
// HMAC с хэш-функцией Стрибог (ГОСТ Р 34.11-2012)
//
// Стандарты:
//   ГОСТ Р 34.11-2012 — хэш-функция Стрибог
//   Р 50.1.113-2016    — HMAC на основе Стрибог-256/512
//   RFC 2104           — общее определение HMAC
//   RFC 7836           — применение HMAC-Стрибог в TLS
//
// Алгоритм:
//   HMAC(K, m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m))
//   где H — Стрибог, K' — ключ, выровненный до длины блока (64 байта)
//
// Применения:
//   - Аутентификация сообщений в ГОСТ-совместимых протоколах
//   - KDF (производные ключи через HMAC-PRF, аналог HKDF)
//   - Имитовставки при отсутствии аппаратного ускорителя Магмы
//
// Постквантовый статус: СТОЙКИЙ (HMAC на основе стойкой хэш-функции
//   безопасен к квантовым атакам).
// ─────────────────────────────────────────────────────────────────────────────
#include <cstdint>
#include <vector>
#include <array>
#include "streebog.hpp"

namespace gost {

// HMAC-Стрибог-256 (вывод 256 бит = 32 байта)
Digest256 hmac_streebog256(const std::vector<uint8_t>& key,
                           const uint8_t* data, size_t len);
Digest256 hmac_streebog256(const std::vector<uint8_t>& key,
                           const std::vector<uint8_t>& data);

// HMAC-Стрибог-512 (вывод 512 бит = 64 байта)
Digest512 hmac_streebog512(const std::vector<uint8_t>& key,
                           const uint8_t* data, size_t len);
Digest512 hmac_streebog512(const std::vector<uint8_t>& key,
                           const std::vector<uint8_t>& data);

// Потоковый HMAC-Стрибог-256
class HmacStreebog256 {
public:
    explicit HmacStreebog256(const std::vector<uint8_t>& key);
    ~HmacStreebog256();
    HmacStreebog256(const HmacStreebog256&) = delete;

    void update(const uint8_t* data, size_t len);
    void update(const std::vector<uint8_t>& data);
    Digest256 finalize();

private:
    struct Impl;
    Impl* impl_;
};

// KDF на основе HMAC-Стрибог (аналог HKDF — RFC 5869)
// Применяется в протоколах на основе ГОСТ
std::vector<uint8_t> hkdf_streebog256(
    const std::vector<uint8_t>& ikm,     // Исходный ключевой материал
    const std::vector<uint8_t>& salt,    // Соль (может быть пустой)
    const std::vector<uint8_t>& info,    // Контекстная информация
    size_t output_len                     // Длина производного ключа (байт)
);

// HMAC-based Key Derivation Function (стандарт Р 50.1.113-2016)
std::vector<uint8_t> kdf_gostr3411_2012_256(
    const std::vector<uint8_t>& key,
    const std::string& label,
    const std::vector<uint8_t>& seed
);

} // namespace gost