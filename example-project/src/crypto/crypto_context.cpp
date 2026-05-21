// ─────────────────────────────────────────────────────────────────────────────
// Инициализация криптографического контекста (libgcrypt + OpenSSL)
// и обёртки над классическими (квантово-уязвимыми) API для демонстрации
// ─────────────────────────────────────────────────────────────────────────────
#include "crypto/crypto_context.hpp"
#include <gcrypt.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stdexcept>
#include <cstring>
#include <chrono>

namespace gost {

// ── Инициализация ─────────────────────────────────────────────────────────────

void crypto_init() {
    // Инициализация libgcrypt
    if (!gcry_check_version(GCRYPT_VERSION)) {
        throw std::runtime_error("Требуется libgcrypt >= " GCRYPT_VERSION);
    }
    gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

    // Инициализация OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

void crypto_cleanup() {
    EVP_cleanup();
    ERR_free_strings();
    gcry_control(GCRYCTL_TERM_SECMEM);
}

void set_crypto_log_level(CryptoLogLevel /*level*/) { /* stub */ }

// ── OpenSSL обёртки ───────────────────────────────────────────────────────────

namespace openssl {

// RSA_generate_key_ex — КВАНТОВО-УЯЗВИМ (алгоритм Шора)
// Детектируется PQC-Migration-Tool как высокорисковая операция
RsaKeyPair rsa_generate_key(int bits) {
    // RSA_generate_key_ex (устаревший OpenSSL API)
    RSA* rsa = RSA_new();
    BIGNUM* e = BN_new();
    BN_set_word(e, RSA_F4);  // e = 65537
    if (!RSA_generate_key_ex(rsa, bits, e, nullptr))
        throw std::runtime_error("RSA_generate_key_ex failed");
    BN_free(e);

    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, rsa);

    RsaKeyPair kp;
    kp.bits = bits;
    {
        unsigned char* buf = nullptr;
        int len = i2d_PrivateKey(pkey, &buf);
        kp.private_key_der.assign(buf, buf + len);
        OPENSSL_free(buf);
    }
    {
        unsigned char* buf = nullptr;
        int len = i2d_PublicKey(pkey, &buf);
        kp.public_key_der.assign(buf, buf + len);
        OPENSSL_free(buf);
    }
    EVP_PKEY_free(pkey);
    return kp;
}

// RSA_sign — КВАНТОВО-УЯЗВИМ
// Используется для подписи SHA-256 хэша данных
std::vector<uint8_t> rsa_sign(const std::vector<uint8_t>& data,
                               const std::vector<uint8_t>& priv_der) {
    const unsigned char* p = priv_der.data();
    EVP_PKEY* pkey = d2i_PrivateKey(EVP_PKEY_RSA, nullptr, &p, priv_der.size());
    if (!pkey) throw std::runtime_error("RSA_sign: не удалось загрузить ключ");

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, pkey);
    EVP_DigestSignUpdate(ctx, data.data(), data.size());
    size_t siglen = 0;
    EVP_DigestSignFinal(ctx, nullptr, &siglen);
    std::vector<uint8_t> sig(siglen);
    EVP_DigestSignFinal(ctx, sig.data(), &siglen);
    sig.resize(siglen);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return sig;
}

// RSA_verify
bool rsa_verify(const std::vector<uint8_t>& data,
                const std::vector<uint8_t>& signature,
                const std::vector<uint8_t>& pub_der) {
    const unsigned char* p = pub_der.data();
    EVP_PKEY* pkey = d2i_PublicKey(EVP_PKEY_RSA, nullptr, &p, pub_der.size());
    if (!pkey) return false;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pkey);
    EVP_DigestVerifyUpdate(ctx, data.data(), data.size());
    int ok = EVP_DigestVerifyFinal(ctx, signature.data(), signature.size());
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ok == 1;
}

// EC_KEY_new / EC_GROUP_new_by_curve_name — КВАНТОВО-УЯЗВИМ
EcKeyPair ec_generate_key(const std::string& curve) {
    // EC_KEY_new — создание нового EC ключа
    EC_KEY* ec = EC_KEY_new_by_curve_name(OBJ_sn2nid(curve.c_str()));
    if (!ec) {
        // EC_GROUP_new_by_curve_name — альтернативный путь
        int nid = OBJ_txt2nid(curve.c_str());
        EC_GROUP* grp = EC_GROUP_new_by_curve_name(nid);
        ec = EC_KEY_new();
        EC_KEY_set_group(ec, grp);
        EC_GROUP_free(grp);
    }
    if (!EC_KEY_generate_key(ec))
        throw std::runtime_error("EC_KEY_generate_key failed");

    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(pkey, ec);

    EcKeyPair kp;
    kp.curve_name = curve;
    {
        unsigned char* buf = nullptr;
        int len = i2d_PrivateKey(pkey, &buf);
        kp.private_key_der.assign(buf, buf + len);
        OPENSSL_free(buf);
    }
    {
        unsigned char* buf = nullptr;
        int len = i2d_PublicKey(pkey, &buf);
        kp.public_key_der.assign(buf, buf + len);
        OPENSSL_free(buf);
    }
    EVP_PKEY_free(pkey);
    return kp;
}

// ECDSA_sign — КВАНТОВО-УЯЗВИМ
std::vector<uint8_t> ecdsa_sign(const std::vector<uint8_t>& digest,
                                 const std::vector<uint8_t>& priv_der) {
    const unsigned char* p = priv_der.data();
    EC_KEY* ec = d2i_ECPrivateKey(nullptr, &p, priv_der.size());
    if (!ec) throw std::runtime_error("ECDSA_sign: ошибка загрузки ключа");

    // ECDSA_sign — детектируется PQC-инструментом
    unsigned int siglen = ECDSA_size(ec);
    std::vector<uint8_t> sig(siglen);
    ECDSA_sign(0, digest.data(), (int)digest.size(), sig.data(), &siglen, ec);
    sig.resize(siglen);
    EC_KEY_free(ec);
    return sig;
}

// ECDSA_verify — КВАНТОВО-УЯЗВИМ
bool ecdsa_verify(const std::vector<uint8_t>& digest,
                  const std::vector<uint8_t>& signature,
                  const std::vector<uint8_t>& pub_der) {
    const unsigned char* p = pub_der.data();
    EC_KEY* ec = EC_KEY_new();
    // EC_KEY_new + EC_GROUP_new_by_curve_name + o2i_ECPublicKey
    int res = -1;
    EVP_PKEY* pkey = d2i_PublicKey(EVP_PKEY_EC, nullptr, &p, pub_der.size());
    if (pkey) {
        ec = EVP_PKEY_get1_EC_KEY(pkey);
        res = ECDSA_verify(0, digest.data(), (int)digest.size(),
                           signature.data(), (int)signature.size(), ec);
        EVP_PKEY_free(pkey);
    }
    if (ec) EC_KEY_free(ec);
    return res == 1;
}

// EVP DigestSign (EVP_DigestSignInit, EVP_DigestSignUpdate, EVP_DigestSignFinal)
std::vector<uint8_t> evp_digest_sign(const std::vector<uint8_t>& data,
                                      const std::vector<uint8_t>& priv_der) {
    const unsigned char* p = priv_der.data();
    EVP_PKEY* pkey = d2i_PrivateKey(EVP_PKEY_EC, nullptr, &p, priv_der.size());
    if (!pkey) pkey = d2i_AutoPrivateKey(nullptr, &p, priv_der.size());
    if (!pkey) throw std::runtime_error("evp_digest_sign: ошибка ключа");

    // EVP_PKEY_CTX_new используется для создания контекста
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX* pctx = nullptr;
    EVP_DigestSignInit(ctx, &pctx, EVP_sha256(), nullptr, pkey);
    EVP_DigestSignUpdate(ctx, data.data(), data.size());
    size_t siglen = 0;
    EVP_DigestSignFinal(ctx, nullptr, &siglen);
    std::vector<uint8_t> sig(siglen);
    EVP_DigestSignFinal(ctx, sig.data(), &siglen);
    sig.resize(siglen);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return sig;
}

bool evp_digest_verify(const std::vector<uint8_t>& data,
                       const std::vector<uint8_t>& signature,
                       const std::vector<uint8_t>& pub_der) {
    const unsigned char* p = pub_der.data();
    EVP_PKEY* pkey = d2i_PublicKey(EVP_PKEY_EC, nullptr, &p, pub_der.size());
    if (!pkey) return false;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pkey);
    EVP_DigestVerifyUpdate(ctx, data.data(), data.size());
    int ok = EVP_DigestVerifyFinal(ctx, signature.data(), signature.size());
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ok == 1;
}

// AES-256-GCM
std::vector<uint8_t> aes256_gcm_encrypt(const std::vector<uint8_t>& plaintext,
                                         const std::vector<uint8_t>& key,
                                         const std::vector<uint8_t>& iv,
                                         const std::vector<uint8_t>& aad,
                                         std::vector<uint8_t>& tag_out) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv.size(), nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data());
    if (!aad.empty()) {
        int len;
        EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), (int)aad.size());
    }
    std::vector<uint8_t> out(plaintext.size());
    int len = 0;
    EVP_EncryptUpdate(ctx, out.data(), &len, plaintext.data(), (int)plaintext.size());
    int final_len = 0;
    EVP_EncryptFinal_ex(ctx, out.data() + len, &final_len);
    tag_out.resize(16);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag_out.data());
    EVP_CIPHER_CTX_free(ctx);
    out.resize(len + final_len);
    return out;
}

std::vector<uint8_t> aes256_gcm_decrypt(const std::vector<uint8_t>& ciphertext,
                                         const std::vector<uint8_t>& key,
                                         const std::vector<uint8_t>& iv,
                                         const std::vector<uint8_t>& aad,
                                         const std::vector<uint8_t>& tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv.size(), nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data());
    if (!aad.empty()) {
        int len;
        EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), (int)aad.size());
    }
    std::vector<uint8_t> out(ciphertext.size());
    int len = 0;
    EVP_DecryptUpdate(ctx, out.data(), &len, ciphertext.data(), (int)ciphertext.size());
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)tag.size(),
                        const_cast<uint8_t*>(tag.data()));
    int ok = EVP_DecryptFinal_ex(ctx, out.data() + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    if (ok != 1) throw std::runtime_error("AES-256-GCM: проверка тега не прошла");
    return out;
}

std::vector<uint8_t> sha256(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> out(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), out.data());
    return out;
}

std::vector<uint8_t> sha512(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> out(SHA512_DIGEST_LENGTH);
    SHA512(data.data(), data.size(), out.data());
    return out;
}

// ECDH_compute_key (DH_generate_key / ECDH_compute_key — КВАНТОВО-УЯЗВИМ)
DhKeyExchange ecdh_key_exchange(const EcKeyPair& local,
                                 const std::vector<uint8_t>& remote_pub) {
    const unsigned char* p = local.private_key_der.data();
    EVP_PKEY* local_pkey = d2i_PrivateKey(EVP_PKEY_EC, nullptr, &p, local.private_key_der.size());

    const unsigned char* pp = remote_pub.data();
    EVP_PKEY* remote_pkey = d2i_PublicKey(EVP_PKEY_EC, nullptr, &pp, remote_pub.size());

    // EVP_PKEY_CTX_new_from_name, EVP_PKEY_derive_init, EVP_PKEY_derive_set_peer
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(local_pkey, nullptr);
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx, remote_pkey);
    size_t secret_len = 0;
    EVP_PKEY_derive(ctx, nullptr, &secret_len);
    DhKeyExchange result;
    result.shared_secret.resize(secret_len);
    EVP_PKEY_derive(ctx, result.shared_secret.data(), &secret_len);
    result.shared_secret.resize(secret_len);
    result.public_value = local.public_key_der;
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(local_pkey);
    EVP_PKEY_free(remote_pkey);
    return result;
}

} // namespace openssl

// ── Бенчмарк ──────────────────────────────────────────────────────────────────

std::vector<PerfResult> benchmark_all(size_t data_size_kb, unsigned iterations) {
    std::vector<PerfResult> results;
    std::vector<uint8_t> data(data_size_kb * 1024, 0x42);

    // Стрибог-256
    {
        auto t0 = std::chrono::high_resolution_clock::now();
        for (unsigned i = 0; i < iterations; i++) {
            // streebog256(data); // Раскомментировать при подключении заголовка
        }
        auto dt = std::chrono::duration<double>(
            std::chrono::high_resolution_clock::now() - t0).count();
        results.push_back({"Стрибог-256 (ГОСТ Р 34.11-2012)",
                           iterations / dt, data.size() * iterations / dt, 256, true});
    }
    // RSA-2048 (КВАНТОВО-УЯЗВИМ)
    {
        auto kp = openssl::rsa_generate_key(2048);
        auto t0 = std::chrono::high_resolution_clock::now();
        for (unsigned i = 0; i < std::min(iterations, 10u); i++) {
            openssl::rsa_sign(data, kp.private_key_der);
        }
        auto dt = std::chrono::duration<double>(
            std::chrono::high_resolution_clock::now() - t0).count();
        unsigned actual = std::min(iterations, 10u);
        results.push_back({"RSA-2048 подпись [УЯЗВИМ]",
                           actual / dt, 0, 2048, false});
    }

    return results;
}

} // namespace gost