#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// Кузнечик — блочный шифр ГОСТ Р 34.12-2015 (Grasshopper / Kuznechik)
//
// Характеристики:
//   Длина блока:  128 бит (16 байт)
//   Длина ключа:  256 бит (32 байта)
//   Число раундов: 10
//   Операции: S (нелинейная замена π), L (линейное преобразование),
//             X (XOR с раундовым ключом)
//
// Стандарты:
//   ГОСТ Р 34.12-2015 — основной стандарт (Кузнечик)
//   RFC 7801           — описание алгоритма
//   ГОСТ Р 34.13-2015 — режимы работы шифра
//   TC26               — рекомендации по применению
//
// Режимы работы согласно ГОСТ Р 34.13-2015:
//   ECB — простая замена (не рекомендуется без дополнительных мер)
//   CBC — сцепление блоков шифртекста
//   CFB — обратная связь по шифртексту
//   OFB — обратная связь по выходу
//   CTR — счётчик (рекомендован для потокового шифрования)
//   CTR-ACPKM — расширенный счётчик (Р 1323565.1.017-2018)
//
// Постквантовый статус: СТОЙКИЙ (симметричные шифры с ключом 256 бит
//   сохраняют 128-битную квантовую стойкость при атаке Гровера).
//
// Примечание: данная реализация является эталонной. Для максимальной
// производительности рекомендуется использовать аппаратные ускорители
// или оптимизированные SIMD-реализации.
// ─────────────────────────────────────────────────────────────────────────────
#include <cstdint>
#include <array>
#include <vector>
#include <stdexcept>

namespace gost {

constexpr size_t GRASSHOPPER_BLOCK_SIZE = 16;  // 128 бит
constexpr size_t GRASSHOPPER_KEY_SIZE   = 32;  // 256 бит
constexpr size_t GRASSHOPPER_ROUNDS     = 10;

using GBlock = std::array<uint8_t, GRASSHOPPER_BLOCK_SIZE>;
using GKey   = std::array<uint8_t, GRASSHOPPER_KEY_SIZE>;

// Режимы шифрования (ГОСТ Р 34.13-2015)
enum class CipherMode { ECB, CBC, CTR, CFB, OFB };

class Grasshopper {
public:
    // Инициализация ключём (ГОСТ Р 34.12-2015, раздел 4.3 — расширение ключа)
    explicit Grasshopper(const GKey& key);
    explicit Grasshopper(const uint8_t* key, size_t len);
    ~Grasshopper();

    // Низкоуровневые операции (один блок)
    GBlock encrypt_block(const GBlock& plaintext) const;
    GBlock decrypt_block(const GBlock& ciphertext) const;

    // Шифрование в режиме CTR (ГОСТ Р 34.13-2015, раздел 5.4)
    // Рекомендованный режим для потокового шифрования
    std::vector<uint8_t> encrypt_ctr(const std::vector<uint8_t>& data,
                                     const std::array<uint8_t, 8>& iv) const;
    std::vector<uint8_t> decrypt_ctr(const std::vector<uint8_t>& data,
                                     const std::array<uint8_t, 8>& iv) const;

    // Шифрование в режиме CBC (ГОСТ Р 34.13-2015, раздел 5.2)
    std::vector<uint8_t> encrypt_cbc(const std::vector<uint8_t>& plaintext,
                                     const GBlock& iv) const;
    std::vector<uint8_t> decrypt_cbc(const std::vector<uint8_t>& ciphertext,
                                     const GBlock& iv) const;

    // Режим имитовставки (MAC) — ГОСТ Р 34.13-2015, раздел 5.7
    std::array<uint8_t, 8> mac(const std::vector<uint8_t>& data) const;

    // Проверка таблиц — верификация по эталонным значениям ГОСТ Р 34.12-2015
    static bool verify_sbox();

private:
    struct RoundKeys {
        GBlock keys[GRASSHOPPER_ROUNDS];
    };

    RoundKeys rk_;

    // Операции раунда
    static void apply_s(GBlock& block);           // π — нелинейная замена
    static void apply_s_inv(GBlock& block);        // π⁻¹ — обратная замена
    static void apply_p(GBlock& block);            // τ — перестановка байт
    static void apply_p_inv(GBlock& block);
    static void apply_l(GBlock& block);            // λ — линейное преобразование
    static void apply_l_inv(GBlock& block);
    static uint8_t gf_mul(uint8_t a, uint8_t b);  // Умножение в GF(2^8)

    void expand_key(const uint8_t* key);

    // Таблицы (π S-box и коэффициенты λ согласно ГОСТ Р 34.12-2015)
    static const uint8_t PI[256];
    static const uint8_t PI_INV[256];
    static const uint8_t LINEAR_COEFF[16];  // Коэффициенты линейного преобразования λ
};

} // namespace gost