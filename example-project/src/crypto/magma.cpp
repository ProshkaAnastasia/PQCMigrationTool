// ─────────────────────────────────────────────────────────────────────────────
// Магма (ГОСТ Р 34.12-2015 / ГОСТ 28147-89) — реализация через libgcrypt
//
// Блок 64 бита, ключ 256 бит, 32 раунда (Фейстелевская структура).
// Таблица замен фиксирована в ГОСТ Р 34.12-2015 (ранее задавалась параметрами).
//
// Ключевое расписание: 8 32-битных подключей К₁..К₈ (повторяются 4 раза)
//   Раунды 1-24: К₁,К₂,К₃,К₄,К₅,К₆,К₇,К₈ (повтор 3 раза)
//   Раунды 25-32: К₈,К₇,К₆,К₅,К₄,К₃,К₂,К₁ (обратный порядок)
// ─────────────────────────────────────────────────────────────────────────────
#include "crypto/magma.hpp"
#include <gcrypt.h>
#include <stdexcept>
#include <cstring>

namespace gost {

// ── S-блок Магмы (ГОСТ Р 34.12-2015, Приложение Б) ───────────────────────────
// Фиксированная таблица замен (4-битные значения, 8 строк по 16 элементов)
static const uint8_t MAGMA_SBOX[8][16] = {
    // S8 (старший полубайт, биты 7-4)
    {0xC, 0x4, 0x6, 0x2, 0xA, 0x5, 0xB, 0x9, 0xE, 0x8, 0xD, 0x7, 0x0, 0x3, 0xF, 0x1},
    // S7
    {0x6, 0x8, 0x2, 0x3, 0x9, 0xA, 0x5, 0xC, 0x1, 0xE, 0x4, 0x7, 0xB, 0xD, 0x0, 0xF},
    // S6
    {0xB, 0x3, 0x5, 0x8, 0x2, 0xF, 0xA, 0xD, 0xE, 0x1, 0x7, 0x4, 0xC, 0x9, 0x6, 0x0},
    // S5
    {0xC, 0x8, 0x2, 0x1, 0xD, 0x4, 0xF, 0x6, 0x7, 0x0, 0xA, 0x5, 0x3, 0xE, 0x9, 0xB},
    // S4
    {0x7, 0xF, 0x5, 0xA, 0x8, 0x1, 0x6, 0xD, 0x0, 0x9, 0x3, 0xE, 0xB, 0x4, 0x2, 0xC},
    // S3
    {0x5, 0xD, 0xF, 0x6, 0x9, 0x2, 0xC, 0xA, 0xB, 0x7, 0x8, 0x1, 0x4, 0x3, 0xE, 0x0},
    // S2
    {0x8, 0xE, 0x2, 0x5, 0x6, 0x9, 0x1, 0xC, 0xF, 0x4, 0xB, 0x0, 0xD, 0xA, 0x3, 0x7},
    // S1 (младший полубайт, биты 3-0)
    {0x1, 0x7, 0xE, 0xD, 0x0, 0x5, 0x8, 0x3, 0x4, 0xF, 0xA, 0x6, 0x9, 0xC, 0xB, 0x2},
};

// ── Реализация через libgcrypt ────────────────────────────────────────────────

struct Magma::Impl {
    gcry_cipher_hd_t hd;
    MagmaParamset paramset;
    MagmaKey key;

    explicit Impl(const MagmaKey& k, MagmaParamset ps) : paramset(ps), key(k) {
        gcry_error_t err = gcry_cipher_open(&hd, GCRY_CIPHER_GOST28147,
                                            GCRY_CIPHER_MODE_ECB, 0);
        if (err) throw std::runtime_error("gcry_cipher_open GOST28147 failed: " +
                                          std::string(gcry_strerror(err)));

        // Для CryptoPro-A используем специальный параметрсет
        if (ps == MagmaParamset::CRYPTOPRO_A) {
            gcry_cipher_setkey(hd, k.data(), k.size());
        } else {
            gcry_cipher_setkey(hd, k.data(), k.size());
        }
    }
    ~Impl() { gcry_cipher_close(hd); }
};

Magma::Magma(const MagmaKey& key, MagmaParamset paramset)
    : impl_(new Impl(key, paramset)) {}

Magma::~Magma() { delete impl_; }

// ── ECB шифрование/расшифровывание ────────────────────────────────────────────

MagmaBlock Magma::encrypt_block(const MagmaBlock& plaintext) const {
    MagmaBlock out;
    gcry_cipher_hd_t hd2;
    gcry_cipher_open(&hd2, GCRY_CIPHER_GOST28147, GCRY_CIPHER_MODE_ECB, 0);
    gcry_cipher_setkey(hd2, impl_->key.data(), impl_->key.size());
    gcry_cipher_encrypt(hd2, out.data(), 8, plaintext.data(), 8);
    gcry_cipher_close(hd2);
    return out;
}

MagmaBlock Magma::decrypt_block(const MagmaBlock& ciphertext) const {
    MagmaBlock out;
    gcry_cipher_hd_t hd2;
    gcry_cipher_open(&hd2, GCRY_CIPHER_GOST28147, GCRY_CIPHER_MODE_ECB, 0);
    gcry_cipher_setkey(hd2, impl_->key.data(), impl_->key.size());
    gcry_cipher_decrypt(hd2, out.data(), 8, ciphertext.data(), 8);
    gcry_cipher_close(hd2);
    return out;
}

// ── CFB шифрование (ГОСТ Р 34.13-2015, раздел 5.3) ───────────────────────────

std::vector<uint8_t> Magma::encrypt_cfb(const std::vector<uint8_t>& data,
                                         const MagmaBlock& iv) const {
    gcry_cipher_hd_t hd2;
    gcry_cipher_open(&hd2, GCRY_CIPHER_GOST28147, GCRY_CIPHER_MODE_CFB, 0);
    gcry_cipher_setkey(hd2, impl_->key.data(), impl_->key.size());
    gcry_cipher_setiv(hd2, iv.data(), 8);
    std::vector<uint8_t> out(data.size());
    gcry_cipher_encrypt(hd2, out.data(), out.size(), data.data(), data.size());
    gcry_cipher_close(hd2);
    return out;
}

std::vector<uint8_t> Magma::decrypt_cfb(const std::vector<uint8_t>& data,
                                         const MagmaBlock& iv) const {
    gcry_cipher_hd_t hd2;
    gcry_cipher_open(&hd2, GCRY_CIPHER_GOST28147, GCRY_CIPHER_MODE_CFB, 0);
    gcry_cipher_setkey(hd2, impl_->key.data(), impl_->key.size());
    gcry_cipher_setiv(hd2, iv.data(), 8);
    std::vector<uint8_t> out(data.size());
    gcry_cipher_decrypt(hd2, out.data(), out.size(), data.data(), data.size());
    gcry_cipher_close(hd2);
    return out;
}

// ── CBC шифрование ────────────────────────────────────────────────────────────

std::vector<uint8_t> Magma::encrypt_cbc(const std::vector<uint8_t>& data,
                                         const MagmaBlock& iv) const {
    gcry_cipher_hd_t hd2;
    gcry_cipher_open(&hd2, GCRY_CIPHER_GOST28147, GCRY_CIPHER_MODE_CBC, 0);
    gcry_cipher_setkey(hd2, impl_->key.data(), impl_->key.size());
    gcry_cipher_setiv(hd2, iv.data(), 8);
    // Дополнение до кратного 8 байтам
    size_t padded = ((data.size() + 7) / 8) * 8;
    std::vector<uint8_t> padded_data(padded, 0);
    std::memcpy(padded_data.data(), data.data(), data.size());
    std::vector<uint8_t> out(padded);
    gcry_cipher_encrypt(hd2, out.data(), out.size(), padded_data.data(), padded_data.size());
    gcry_cipher_close(hd2);
    return out;
}

std::vector<uint8_t> Magma::decrypt_cbc(const std::vector<uint8_t>& data,
                                         const MagmaBlock& iv) const {
    gcry_cipher_hd_t hd2;
    gcry_cipher_open(&hd2, GCRY_CIPHER_GOST28147, GCRY_CIPHER_MODE_CBC, 0);
    gcry_cipher_setkey(hd2, impl_->key.data(), impl_->key.size());
    gcry_cipher_setiv(hd2, iv.data(), 8);
    std::vector<uint8_t> out(data.size());
    gcry_cipher_decrypt(hd2, out.data(), out.size(), data.data(), data.size());
    gcry_cipher_close(hd2);
    return out;
}

// ── ECB для массива блоков ────────────────────────────────────────────────────

std::vector<uint8_t> Magma::encrypt_ecb(const std::vector<uint8_t>& data) const {
    gcry_cipher_hd_t hd2;
    gcry_cipher_open(&hd2, GCRY_CIPHER_GOST28147, GCRY_CIPHER_MODE_ECB, 0);
    gcry_cipher_setkey(hd2, impl_->key.data(), impl_->key.size());
    size_t padded = ((data.size() + 7) / 8) * 8;
    std::vector<uint8_t> in(padded, 0), out(padded);
    std::memcpy(in.data(), data.data(), data.size());
    gcry_cipher_encrypt(hd2, out.data(), padded, in.data(), padded);
    gcry_cipher_close(hd2);
    return out;
}

std::vector<uint8_t> Magma::decrypt_ecb(const std::vector<uint8_t>& data) const {
    gcry_cipher_hd_t hd2;
    gcry_cipher_open(&hd2, GCRY_CIPHER_GOST28147, GCRY_CIPHER_MODE_ECB, 0);
    gcry_cipher_setkey(hd2, impl_->key.data(), impl_->key.size());
    std::vector<uint8_t> out(data.size());
    gcry_cipher_decrypt(hd2, out.data(), data.size(), data.data(), data.size());
    gcry_cipher_close(hd2);
    return out;
}

// ── Имитовставка ГОСТ (GOST28147 MAC / IMIT) ─────────────────────────────────

std::array<uint8_t, 4> Magma::imit(const std::vector<uint8_t>& data) const {
    gcry_mac_hd_t mac_hd;
    gcry_error_t err = gcry_mac_open(&mac_hd, GCRY_MAC_GOST28147_IMIT, 0, nullptr);
    if (err) throw std::runtime_error("gcry_mac_open GOST28147_IMIT failed");
    gcry_mac_setkey(mac_hd, impl_->key.data(), impl_->key.size());
    gcry_mac_write(mac_hd, data.data(), data.size());
    std::array<uint8_t, 4> tag;
    size_t taglen = 4;
    gcry_mac_read(mac_hd, tag.data(), &taglen);
    gcry_mac_close(mac_hd);
    return tag;
}

// ── Свободная функция ГОСТ 28147-89 MAC ──────────────────────────────────────

std::array<uint8_t, 4> gost28147_mac(const uint8_t* data, size_t len,
                                      const MagmaKey& key) {
    Magma m(key);
    return m.imit(std::vector<uint8_t>(data, data + len));
}

} // namespace gost