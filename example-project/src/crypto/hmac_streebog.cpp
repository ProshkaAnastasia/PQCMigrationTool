// ─────────────────────────────────────────────────────────────────────────────
// HMAC-Стрибог через libgcrypt (GCRY_MAC_HMAC_STRIBOG256/512)
// Стандарт: Р 50.1.113-2016
// ─────────────────────────────────────────────────────────────────────────────
#include "crypto/hmac_streebog.hpp"
#include <gcrypt.h>
#include <stdexcept>
#include <cstring>

namespace gost {

// ── HMAC-Стрибог-256 ──────────────────────────────────────────────────────────

Digest256 hmac_streebog256(const std::vector<uint8_t>& key,
                           const uint8_t* data, size_t len) {
    gcry_mac_hd_t hd;
    gcry_error_t err = gcry_mac_open(&hd, GCRY_MAC_HMAC_STRIBOG256, 0, nullptr);
    if (err) throw std::runtime_error("gcry_mac_open HMAC_STRIBOG256 failed");
    gcry_mac_setkey(hd, key.data(), key.size());
    gcry_mac_write(hd, data, len);
    Digest256 out;
    size_t outlen = STREEBOG256_DIGEST_SIZE;
    gcry_mac_read(hd, out.data(), &outlen);
    gcry_mac_close(hd);
    return out;
}

Digest256 hmac_streebog256(const std::vector<uint8_t>& key,
                           const std::vector<uint8_t>& data) {
    return hmac_streebog256(key, data.data(), data.size());
}

// ── HMAC-Стрибог-512 ──────────────────────────────────────────────────────────

Digest512 hmac_streebog512(const std::vector<uint8_t>& key,
                           const uint8_t* data, size_t len) {
    gcry_mac_hd_t hd;
    gcry_error_t err = gcry_mac_open(&hd, GCRY_MAC_HMAC_STRIBOG512, 0, nullptr);
    if (err) throw std::runtime_error("gcry_mac_open HMAC_STRIBOG512 failed");
    gcry_mac_setkey(hd, key.data(), key.size());
    gcry_mac_write(hd, data, len);
    Digest512 out;
    size_t outlen = STREEBOG512_DIGEST_SIZE;
    gcry_mac_read(hd, out.data(), &outlen);
    gcry_mac_close(hd);
    return out;
}

Digest512 hmac_streebog512(const std::vector<uint8_t>& key,
                           const std::vector<uint8_t>& data) {
    return hmac_streebog512(key, data.data(), data.size());
}

// ── Потоковый HMAC-Стрибог-256 ───────────────────────────────────────────────

struct HmacStreebog256::Impl {
    gcry_mac_hd_t hd;
    explicit Impl(const std::vector<uint8_t>& key) {
        gcry_error_t err = gcry_mac_open(&hd, GCRY_MAC_HMAC_STRIBOG256, 0, nullptr);
        if (err) throw std::runtime_error("HmacStreebog256: gcry_mac_open failed");
        gcry_mac_setkey(hd, key.data(), key.size());
    }
    ~Impl() { gcry_mac_close(hd); }
};

HmacStreebog256::HmacStreebog256(const std::vector<uint8_t>& key)
    : impl_(new Impl(key)) {}
HmacStreebog256::~HmacStreebog256() { delete impl_; }

void HmacStreebog256::update(const uint8_t* data, size_t len) {
    gcry_mac_write(impl_->hd, data, len);
}

void HmacStreebog256::update(const std::vector<uint8_t>& data) {
    gcry_mac_write(impl_->hd, data.data(), data.size());
}

Digest256 HmacStreebog256::finalize() {
    Digest256 out;
    size_t outlen = STREEBOG256_DIGEST_SIZE;
    gcry_mac_read(impl_->hd, out.data(), &outlen);
    return out;
}

// ── HKDF на основе HMAC-Стрибог-256 ─────────────────────────────────────────
// RFC 5869 с заменой HMAC-SHA на HMAC-Стрибог-256

std::vector<uint8_t> hkdf_streebog256(
    const std::vector<uint8_t>& ikm,
    const std::vector<uint8_t>& salt,
    const std::vector<uint8_t>& info,
    size_t output_len)
{
    // Шаг 1: Extract — PRK = HMAC-Stribog256(salt, IKM)
    std::vector<uint8_t> actual_salt = salt;
    if (actual_salt.empty()) actual_salt.resize(32, 0);  // Нулевой salt по умолчанию
    auto prk_arr = hmac_streebog256(actual_salt, ikm);
    std::vector<uint8_t> prk(prk_arr.begin(), prk_arr.end());

    // Шаг 2: Expand — T = T1 || T2 || ...
    std::vector<uint8_t> out;
    std::vector<uint8_t> T;  // T(0) = ""
    uint8_t counter = 1;

    while (out.size() < output_len) {
        std::vector<uint8_t> input = T;
        input.insert(input.end(), info.begin(), info.end());
        input.push_back(counter++);
        auto t_arr = hmac_streebog256(prk, input);
        T.assign(t_arr.begin(), t_arr.end());
        out.insert(out.end(), T.begin(), T.end());
    }
    out.resize(output_len);
    return out;
}

// ── KDF согласно Р 50.1.113-2016 ─────────────────────────────────────────────
// KDF(K, label, seed) = HMAC-Stribog256(K, 0x00 || label || 0x00 || seed || L)
// где L = длина выводимого ключа в битах (big-endian uint32)

std::vector<uint8_t> kdf_gostr3411_2012_256(
    const std::vector<uint8_t>& key,
    const std::string& label,
    const std::vector<uint8_t>& seed)
{
    std::vector<uint8_t> input;
    input.push_back(0x00);
    input.insert(input.end(), label.begin(), label.end());
    input.push_back(0x00);
    input.insert(input.end(), seed.begin(), seed.end());
    // L = 256 бит = 0x00000100
    input.push_back(0x00); input.push_back(0x00);
    input.push_back(0x01); input.push_back(0x00);
    auto h = hmac_streebog256(key, input);
    return std::vector<uint8_t>(h.begin(), h.end());
}

} // namespace gost