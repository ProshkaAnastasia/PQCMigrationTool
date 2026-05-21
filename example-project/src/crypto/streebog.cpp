// ─────────────────────────────────────────────────────────────────────────────
// Стрибог (ГОСТ Р 34.11-2012) — реализация через libgcrypt
//
// Стандарт: ГОСТ Р 34.11-2012, RFC 6986
// Алгоритм: Стрибог-256 (256-бит вывод), Стрибог-512 (512-бит вывод)
// Базовая конструкция: Miyaguchi-Preneel с внутренним шифром E
// ─────────────────────────────────────────────────────────────────────────────
#include "crypto/streebog.hpp"
#include <gcrypt.h>
#include <stdexcept>
#include <cstring>

namespace gost {

// ── Streebog256Context::Impl ──────────────────────────────────────────────────

struct Streebog256Context::Impl {
    gcry_md_hd_t hd;
    bool finalized = false;

    Impl() {
        gcry_error_t err = gcry_md_open(&hd, GCRY_MD_STRIBOG256, 0);
        if (err) throw std::runtime_error("gcry_md_open(STRIBOG256) failed");
    }
    ~Impl() { gcry_md_close(hd); }
};

Streebog256Context::Streebog256Context() : impl_(new Impl()) {}
Streebog256Context::~Streebog256Context() { delete impl_; }

void Streebog256Context::update(const uint8_t* data, size_t len) {
    gcry_md_write(impl_->hd, data, len);
}

void Streebog256Context::update(const std::vector<uint8_t>& data) {
    gcry_md_write(impl_->hd, data.data(), data.size());
}

Digest256 Streebog256Context::finalize() {
    gcry_md_final(impl_->hd);
    const uint8_t* p = gcry_md_read(impl_->hd, GCRY_MD_STRIBOG256);
    Digest256 out;
    std::memcpy(out.data(), p, STREEBOG256_DIGEST_SIZE);
    return out;
}

// ── Streebog512Context::Impl ──────────────────────────────────────────────────

struct Streebog512Context::Impl {
    gcry_md_hd_t hd;
    Impl() {
        gcry_error_t err = gcry_md_open(&hd, GCRY_MD_STRIBOG512, 0);
        if (err) throw std::runtime_error("gcry_md_open(STRIBOG512) failed");
    }
    ~Impl() { gcry_md_close(hd); }
};

Streebog512Context::Streebog512Context() : impl_(new Impl()) {}
Streebog512Context::~Streebog512Context() { delete impl_; }

void Streebog512Context::update(const uint8_t* data, size_t len) {
    gcry_md_write(impl_->hd, data, len);
}

void Streebog512Context::update(const std::vector<uint8_t>& data) {
    gcry_md_write(impl_->hd, data.data(), data.size());
}

Digest512 Streebog512Context::finalize() {
    gcry_md_final(impl_->hd);
    const uint8_t* p = gcry_md_read(impl_->hd, GCRY_MD_STRIBOG512);
    Digest512 out;
    std::memcpy(out.data(), p, STREEBOG512_DIGEST_SIZE);
    return out;
}

// ── Утилиты одного вызова ─────────────────────────────────────────────────────

static Digest256 gcrypt_streebog256(const uint8_t* data, size_t len) {
    gcry_md_hd_t hd;
    gcry_error_t err = gcry_md_open(&hd, GCRY_MD_STRIBOG256, 0);
    if (err) throw std::runtime_error("gcry_md_open STRIBOG256");
    gcry_md_write(hd, data, len);
    gcry_md_final(hd);
    Digest256 out;
    std::memcpy(out.data(), gcry_md_read(hd, GCRY_MD_STRIBOG256), STREEBOG256_DIGEST_SIZE);
    gcry_md_close(hd);
    return out;
}

static Digest512 gcrypt_streebog512(const uint8_t* data, size_t len) {
    gcry_md_hd_t hd;
    gcry_error_t err = gcry_md_open(&hd, GCRY_MD_STRIBOG512, 0);
    if (err) throw std::runtime_error("gcry_md_open STRIBOG512");
    gcry_md_write(hd, data, len);
    gcry_md_final(hd);
    Digest512 out;
    std::memcpy(out.data(), gcry_md_read(hd, GCRY_MD_STRIBOG512), STREEBOG512_DIGEST_SIZE);
    gcry_md_close(hd);
    return out;
}

Digest256 streebog256(const uint8_t* data, size_t len) {
    return gcrypt_streebog256(data, len);
}

Digest256 streebog256(const std::vector<uint8_t>& data) {
    return gcrypt_streebog256(data.data(), data.size());
}

Digest256 streebog256(const std::string& data) {
    return gcrypt_streebog256(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

Digest512 streebog512(const uint8_t* data, size_t len) {
    return gcrypt_streebog512(data, len);
}

Digest512 streebog512(const std::vector<uint8_t>& data) {
    return gcrypt_streebog512(data.data(), data.size());
}

Digest512 streebog512(const std::string& data) {
    return gcrypt_streebog512(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

// ── ГОСТ Р 34.11-94 (устаревший) через libgcrypt ─────────────────────────────

std::vector<uint8_t> gostr3411_94(const uint8_t* data, size_t len,
                                   const std::string& /*paramset*/) {
    // ВНИМАНИЕ: ГОСТ Р 34.11-94 квантово-уязвим, используйте Стрибог.
    // Параметрсет CryptoPro-A (id-Gost28147-89-CryptoPro-A-ParamSet).
    gcry_md_hd_t hd;
    gcry_error_t err = gcry_md_open(&hd, GCRY_MD_GOSTR3411_CP, 0);
    if (err) {
        // Fallback: GOSTR3411_94 если CP не доступен
        err = gcry_md_open(&hd, GCRY_MD_GOSTR3411_94, 0);
        if (err) throw std::runtime_error("gcry_md_open GOSTR3411_94 failed");
    }
    gcry_md_write(hd, data, len);
    gcry_md_final(hd);
    const uint8_t* p = gcry_md_read(hd, GCRY_MD_GOSTR3411_94);
    std::vector<uint8_t> out(p, p + 32);
    gcry_md_close(hd);
    return out;
}

} // namespace gost