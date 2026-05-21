#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// Магма — блочный шифр ГОСТ Р 34.12-2015 (ранее ГОСТ 28147-89)
// Реализация через libgcrypt (GCRY_CIPHER_GOST28147)
//
// Характеристики:
//   Длина блока:  64 бита (8 байт)
//   Длина ключа:  256 бит (32 байта)
//   Структура:    сеть Фейстеля, 32 раунда
//   Таблица замен: фиксированная (согласно ГОСТ Р 34.12-2015)
//
// Стандарты:
//   ГОСТ 28147-89       — исходный стандарт (утратил силу в части параметров)
//   ГОСТ Р 34.12-2015   — актуальный стандарт (Магма с фиксированными S-блоками)
//   ГОСТ Р 34.13-2015   — режимы работы
//   RFC 5830            — ГОСТ 28147-89 в интернациональном контексте
//
// Режимы работы:
//   Простая замена (ECB), сцепление блоков (CBC),
//   гаммирование (CFB/OFB), режим с обратной связью,
//   выработка имитовставки (MAC/IMIT)
//
// Постквантовый статус: СТОЙКИЙ при ключе 256 бит (128-битная квантовая
//   стойкость при атаке Гровера). Блок 64 бита допускает атаки типа
//   birthday при большом объёме данных (Birthday Bound ≈ 2^32 блока).
//   РЕКОМЕНДАЦИЯ: для новых протоколов предпочтительнее Кузнечик (128-бит блок).
//
// ВНИМАНИЕ: Использование ГОСТ 28147-89 с нестандартными S-блоками
//   (например, TestParamSet) ЗАПРЕЩЕНО для защиты гостайны.
//   Используйте только сертифицированные параметры.
// ─────────────────────────────────────────────────────────────────────────────
#include <cstdint>
#include <array>
#include <vector>

namespace gost {

constexpr size_t MAGMA_BLOCK_SIZE = 8;   // 64 бита
constexpr size_t MAGMA_KEY_SIZE   = 32;  // 256 бит

using MagmaBlock = std::array<uint8_t, MAGMA_BLOCK_SIZE>;
using MagmaKey   = std::array<uint8_t, MAGMA_KEY_SIZE>;

// Наборы параметров (S-блоки)
enum class MagmaParamset {
    GOST_R_34_12_2015,  // Стандартный (ГОСТ Р 34.12-2015) — РЕКОМЕНДОВАН
    CRYPTOPRO_A,        // CryptoPro paramset A (id-Gost28147-89-CryptoPro-A-ParamSet)
    TEST,               // Тестовый набор (RFC 4357) — НЕ для продуктива!
};

class Magma {
public:
    // Инициализация ключом через libgcrypt GCRY_CIPHER_GOST28147
    explicit Magma(const MagmaKey& key,
                   MagmaParamset paramset = MagmaParamset::GOST_R_34_12_2015);
    ~Magma();
    Magma(const Magma&) = delete;
    Magma& operator=(const Magma&) = delete;

    // Зашифровывание/расшифровывание одного блока (режим ECB)
    MagmaBlock encrypt_block(const MagmaBlock& plaintext) const;
    MagmaBlock decrypt_block(const MagmaBlock& ciphertext) const;

    // Гаммирование (режим CFB, ГОСТ Р 34.13-2015 раздел 5.3)
    std::vector<uint8_t> encrypt_cfb(const std::vector<uint8_t>& data,
                                     const MagmaBlock& iv) const;
    std::vector<uint8_t> decrypt_cfb(const std::vector<uint8_t>& data,
                                     const MagmaBlock& iv) const;

    // Выработка имитовставки (IMIT, ГОСТ Р 34.13-2015 раздел 5.6)
    // 32-битная имитовставка (половина блока)
    std::array<uint8_t, 4> imit(const std::vector<uint8_t>& data) const;

    // Режим простой замены (ECB) для массива блоков
    std::vector<uint8_t> encrypt_ecb(const std::vector<uint8_t>& data) const;
    std::vector<uint8_t> decrypt_ecb(const std::vector<uint8_t>& data) const;

    // CBC режим
    std::vector<uint8_t> encrypt_cbc(const std::vector<uint8_t>& data,
                                     const MagmaBlock& iv) const;
    std::vector<uint8_t> decrypt_cbc(const std::vector<uint8_t>& data,
                                     const MagmaBlock& iv) const;

private:
    struct Impl;
    Impl* impl_;
};

// ГОСТ 28147-89 в режиме выработки имитовставки (устаревший интерфейс)
// Статус: УСТАРЕВШИЙ — использовать Magma::imit() или HMAC-Стрибог
std::array<uint8_t, 4> gost28147_mac(const uint8_t* data, size_t len,
                                      const MagmaKey& key);

} // namespace gost