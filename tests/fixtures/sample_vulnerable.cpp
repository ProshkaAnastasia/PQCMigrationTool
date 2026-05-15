/**
 * tests/fixtures/sample_vulnerable.cpp
 *
 * Test fixture with intentionally quantum-vulnerable cryptographic calls.
 * Used for functional testing (precision/recall evaluation).
 *
 * Ground truth: 10 expected findings (listed in tests/fixtures/ground_truth.json)
 */
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/dh.h>
#include <openssl/dsa.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/md5.h>

namespace crypto {
namespace tls {

class TLSHandshake {
public:
    /// Generates RSA server key — FINDING #1
    RSA* generate_server_key(int key_bits) {    
        RSA* rsa = RSA_new();
        BIGNUM* e = BN_new();
        BN_set_word(e, RSA_F4);
        RSA_generate_key_ex(rsa, key_bits, e, nullptr); // VULN: RSA keygen
        BN_free(e);
        return rsa;
    }

    /// ECDH key exchange — FINDING #2 (EC_KEY_generate_key) + FINDING #3 (ECDH_compute_key)
    void perform_key_exchange(EC_KEY* local, EC_KEY* remote) {
        unsigned char shared[256];
        EC_KEY* peer = EC_KEY_generate_key(nullptr);           // VULN: EC keygen
        ECDH_compute_key(shared, 256,                          // VULN: ECDH
            EC_KEY_get0_public_key(remote), local, nullptr);
        (void)peer;
    }

    /// ECDSA signature — FINDING #4
    int sign_certificate(const unsigned char* msg, size_t len,
                         unsigned char* sig, EC_KEY* key) {
        ECDSA_sign(0, msg, (int)len, sig, nullptr, key); // VULN: ECDSA
        return 0;
    }
}; // class TLSHandshake

} // namespace tls

namespace storage {

class SecureStore {
    RSA* rsa_key_ = nullptr;
public:
    /// RSA encryption — FINDING #5
    void encrypt_data(const unsigned char* data, int len, unsigned char* out) {
        RSA_public_encrypt(len, data, out, rsa_key_, RSA_PKCS1_OAEP_PADDING); // VULN: RSA encrypt
    }

    /// RSA signing — FINDING #6
    void sign_data(const unsigned char* hash, unsigned int hlen,
                   unsigned char* sig, unsigned int* slen) {
        RSA_sign(NID_sha256, hash, hlen, sig, slen, rsa_key_); // VULN: RSA sign
    }

    /// SHA-1 (classically broken, Grover-weakened) — FINDING #7
    void legacy_hash(const unsigned char* data, size_t len, unsigned char* out) {
        SHA1(data, len, out); // VULN: SHA-1
    }
}; // class SecureStore

} // namespace storage
} // namespace crypto

// DH parameter generation — FINDING #8 + FINDING #9
DH* create_dh_params() {
    DH* dh = DH_new();                                             // VULN: DH
    DH_generate_parameters_ex(dh, 2048, DH_GENERATOR_2, nullptr); // VULN: DH params
    return dh;
}

// MD5 (completely broken) — FINDING #10
void compute_legacy_hash(const unsigned char* data, size_t len, unsigned char* out) {
    MD5(data, len, out); // VULN: MD5
}

// SAFE: AES-256-GCM — should NOT trigger any finding
#include <openssl/evp.h>
void safe_encrypt(const unsigned char* key32, const unsigned char* iv12,
                  const unsigned char* plain, int plen, unsigned char* out) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key32, iv12);
    int out_len = 0;
    EVP_EncryptUpdate(ctx, out, &out_len, plain, plen);
    EVP_CIPHER_CTX_free(ctx);
}
