/**
 * tests/fixtures/sample_vulnerable.cpp
 *
 * Test fixture with intentionally quantum-vulnerable cryptographic calls.
 * Used for functional testing (precision/recall evaluation).
 *
 * ── Ground truth ──────────────────────────────────────────────────────────────
 * Unique quantum-vulnerable call sites: 27
 * Currently known analysis gaps (False Negatives in both analyzers):
 *   [FN-DB] EC_KEY_generate_key   — not in vuln DB (aliased under EC_KEY_new)
 *   [FN-DB] SHA1                  — hash functions absent from vuln DB
 *   [FN-DB] MD5                   — hash functions absent from vuln DB
 *   [FN-DB] DH_generate_params_ex — only DH_generate_key is in vuln DB
 * Argument-conditional detection test:
 *   EVP_PKEY_CTX_new_from_name("RSA")       → SHOULD trigger
 *   EVP_PKEY_CTX_new_from_name("ML-KEM-768") → must NOT trigger (PQC algo)
 *
 * Sections:
 *  A. crypto::tls        – RSA keygen, ECDH, ECDSA
 *  B. crypto::storage    – RSA encrypt/sign, SHA-1 [FN-DB]
 *  C. DH params          – DH_new, DH_generate_parameters_ex [FN-DB]
 *  D. MD5                – MD5 [FN-DB]
 *  E. crypto::evp        – EVP high-level API (arg-conditional + full workflows)
 *  F. crypto::dsa_legacy – explicit DSA_new/DSA_sign (distinct from ECDSA)
 *  G. crypto::ec_ops     – EC_GROUP, EC_KEY_new, EC_KEY_generate_key [FN-DB]
 *  H. crypto::bn_ops     – BN_generate_prime_ex, BN_mod_exp
 *  SAFE                  – AES-256-GCM, ML-KEM (must NOT trigger)
 */
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/obj_mac.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

// ── A. crypto::tls ────────────────────────────────────────────────────────────
namespace crypto {
namespace tls {

class TLSHandshake {
public:
    // RSA server key generation — RSA_new + RSA_generate_key_ex
    RSA* generate_server_key(int key_bits) {
        RSA* rsa = RSA_new();                                       // VULN: RSA_new
        BIGNUM* e = BN_new();
        BN_set_word(e, RSA_F4);
        RSA_generate_key_ex(rsa, key_bits, e, nullptr);             // VULN: RSA_generate_key_ex
        BN_free(e);
        return rsa;
    }

    // ECDH key exchange — EC_KEY_generate_key [FN-DB] + ECDH_compute_key
    void perform_key_exchange(EC_KEY* local, EC_KEY* remote) {
        unsigned char shared[256];
        EC_KEY* peer = EC_KEY_generate_key(nullptr);                // VULN [FN-DB]: EC_KEY_generate_key
        ECDH_compute_key(shared, 256,                               // VULN: ECDH_compute_key
            EC_KEY_get0_public_key(remote), local, nullptr);
        (void)peer;
    }

    // ECDSA signature
    int sign_certificate(const unsigned char* msg, size_t len,
                         unsigned char* sig, EC_KEY* key) {
        ECDSA_sign(0, msg, (int)len, sig, nullptr, key);            // VULN: ECDSA_sign
        return 0;
    }
}; // class TLSHandshake

} // namespace tls

// ── B. crypto::storage ────────────────────────────────────────────────────────
namespace storage {

class SecureStore {
    RSA* rsa_key_ = nullptr;
public:
    void encrypt_data(const unsigned char* data, int len, unsigned char* out) {
        RSA_public_encrypt(len, data, out, rsa_key_,                // VULN: RSA_public_encrypt
                           RSA_PKCS1_OAEP_PADDING);
    }

    void sign_data(const unsigned char* hash, unsigned int hlen,
                   unsigned char* sig, unsigned int* slen) {
        RSA_sign(NID_sha256, hash, hlen, sig, slen, rsa_key_);      // VULN: RSA_sign
    }

    // SHA-1: Grover's algorithm halves security (80→40 bits)
    void legacy_hash(const unsigned char* data, size_t len, unsigned char* out) {
        SHA1(data, len, out);                                       // VULN [FN-DB]: SHA1
    }
}; // class SecureStore

} // namespace storage
} // namespace crypto

// ── C. DH parameter generation ───────────────────────────────────────────────
DH* create_dh_params() {
    DH* dh = DH_new();                                              // VULN: DH_new
    DH_generate_parameters_ex(dh, 2048, DH_GENERATOR_2, nullptr);  // VULN [FN-DB]: DH_generate_parameters_ex
    return dh;
}

// ── D. MD5 ────────────────────────────────────────────────────────────────────
void compute_legacy_hash(const unsigned char* data, size_t len, unsigned char* out) {
    MD5(data, len, out);                                            // VULN [FN-DB]: MD5
}

// ── E. crypto::evp ───────────────────────────────────────────────────────────
// Tests EVP high-level API and argument-conditional detection.
namespace crypto {
namespace evp {

// EVP_PKEY_CTX_new_from_name: vulnerable only when arg is a classical algorithm.
// "RSA" → SHOULD trigger; "ML-KEM-768" → must NOT trigger.
void evp_rsa_keygen_classical() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(              // VULN (arg="RSA")
        nullptr, "RSA", nullptr);
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_keygen_init(ctx);                                    // VULN: EVP_PKEY_keygen_init
    EVP_PKEY_keygen(ctx, &pkey);                                  // VULN: EVP_PKEY_keygen
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
}

// SAFE: same function with PQC algorithm name — must NOT produce a finding
void evp_pqc_keygen_safe() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(              // SAFE: arg="ML-KEM-768"
        nullptr, "ML-KEM-768", nullptr);
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
}

// EVP_PKEY_CTX_new from existing EC/RSA key — unconditionally vulnerable
void evp_ctx_from_key(EVP_PKEY* ec_key) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(ec_key, nullptr);       // VULN: EVP_PKEY_CTX_new
    EVP_PKEY_CTX_free(ctx);
}

// Full EVP signing workflow (ECDSA or RSA via EVP_DigestSign*)
void evp_sign(EVP_PKEY* key, const unsigned char* data, size_t len) {
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(mdctx, nullptr,                            // VULN: EVP_DigestSignInit
                       EVP_sha256(), nullptr, key);
    EVP_DigestSignUpdate(mdctx, data, len);                       // VULN: EVP_DigestSignUpdate
    size_t sig_len = 0;
    EVP_DigestSignFinal(mdctx, nullptr, &sig_len);                // VULN: EVP_DigestSignFinal
    EVP_MD_CTX_free(mdctx);
}

// Full EVP verification workflow
void evp_verify(EVP_PKEY* key, const unsigned char* data, size_t len,
                const unsigned char* sig, size_t sig_len) {
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(mdctx, nullptr,                          // VULN: EVP_DigestVerifyInit
                         EVP_sha256(), nullptr, key);
    EVP_DigestVerifyUpdate(mdctx, data, len);                     // VULN: EVP_DigestVerifyUpdate
    EVP_DigestVerifyFinal(mdctx, sig, sig_len);                   // VULN: EVP_DigestVerifyFinal
    EVP_MD_CTX_free(mdctx);
}

// Full EVP ECDH key derivation workflow
void evp_ecdh_derive(EVP_PKEY* local_key, EVP_PKEY* peer_key) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(local_key, nullptr);    // VULN: EVP_PKEY_CTX_new
    EVP_PKEY_derive_init(ctx);                                    // VULN: EVP_PKEY_derive_init
    EVP_PKEY_derive_set_peer(ctx, peer_key);                      // VULN: EVP_PKEY_derive_set_peer
    size_t secret_len = 0;
    EVP_PKEY_derive(ctx, nullptr, &secret_len);                   // VULN: EVP_PKEY_derive
    EVP_PKEY_CTX_free(ctx);
}

} // namespace evp

// ── F. crypto::dsa_legacy ─────────────────────────────────────────────────────
// Explicit DSA (not ECDSA). Tests that regex doesn't conflate the two.
namespace dsa_legacy {

DSA* setup_dsa() {
    return DSA_new();                                             // VULN: DSA_new
}

int sign_with_dsa(DSA* dsa, const unsigned char* dgst, int dlen,
                  unsigned char* sig, unsigned int* siglen) {
    return DSA_sign(0, dgst, dlen, sig, siglen, dsa);            // VULN: DSA_sign
}

} // namespace dsa_legacy

// ── G. crypto::ec_ops ─────────────────────────────────────────────────────────
// EC group allocation + EC_KEY_new + EC_KEY_generate_key (also FN-DB).
namespace ec_ops {

EC_KEY* make_ec_key_p256() {
    EC_GROUP* grp = EC_GROUP_new_by_curve_name(                   // VULN: EC_GROUP_new_by_curve_name
        NID_X9_62_prime256v1);
    EC_KEY* key = EC_KEY_new();                                   // VULN: EC_KEY_new
    EC_KEY_set_group(key, grp);
    EC_KEY_generate_key(key);                                     // VULN [FN-DB]: EC_KEY_generate_key
    EC_GROUP_free(grp);
    return key;
}

} // namespace ec_ops

// ── H. crypto::bn_ops ─────────────────────────────────────────────────────────
// Manual big-number crypto ops that indicate low-level RSA/DH implementation.
namespace bn_ops {

void generate_rsa_prime(int bits) {
    BIGNUM* p = BN_new();
    BN_generate_prime_ex(p, bits, 1, nullptr, nullptr, nullptr); // VULN: BN_generate_prime_ex
    BN_free(p);
}

// Modular exponentiation: core of RSA and DH, solvable via Shor
void manual_mod_exp(BIGNUM* r, const BIGNUM* a,
                    const BIGNUM* p, const BIGNUM* m, BN_CTX* ctx) {
    BN_mod_exp(r, a, p, m, ctx);                                 // VULN: BN_mod_exp
}

} // namespace bn_ops
} // namespace crypto

// ── SAFE ──────────────────────────────────────────────────────────────────────
// None of the following should produce findings.

// AES-256-GCM: symmetric, 256-bit key → Grover gives 128-bit quantum security (acceptable)
void safe_aes_encrypt(const unsigned char* key32, const unsigned char* iv12,
                      const unsigned char* plain, int plen, unsigned char* out) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key32, iv12);
    int out_len = 0;
    EVP_EncryptUpdate(ctx, out, &out_len, plain, plen);
    EVP_CIPHER_CTX_free(ctx);
}

// EVP_PKEY_CTX_new_from_name with ML-KEM-768: post-quantum, must NOT trigger
void safe_pqc_kem() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "ML-KEM-768", nullptr);
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
}
