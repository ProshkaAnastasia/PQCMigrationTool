#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// Криптографический контекст — инициализация и управление провайдерами
//
// Обёртки над низкоуровневыми API OpenSSL и libgcrypt.
// Производит инициализацию, настройку и очистку библиотек.
// ─────────────────────────────────────────────────────────────────────────────
#include <cstdint>
#include <string>
#include <vector>
#include <functional>

namespace gost {

// Инициализация всех криптографических библиотек
// Должна быть вызвана один раз в начале работы приложения
void crypto_init();
void crypto_cleanup();

// Уровни журналирования для криптографических операций
enum class CryptoLogLevel { OFF, ERROR, WARN, INFO, DEBUG };
void set_crypto_log_level(CryptoLogLevel level);

// Обёртки OpenSSL для устаревших функций с нужными именами
// (Эти функции детектируются инструментом PQC-Migration-Tool)
namespace openssl {

// RSA (КВАНТОВО-УЯЗВИМ — ГОСТ ТК 26: подлежит замене)
struct RsaKeyPair {
    std::vector<uint8_t> private_key_der;
    std::vector<uint8_t> public_key_der;
    int bits;
};

// RSA_generate_key_ex — использование: УСТАРЕВШИЙ, детектируется PQC-инструментом
RsaKeyPair rsa_generate_key(int bits = 2048);

// RSA_sign / RSA_verify — УСТАРЕВШИЕ функции
std::vector<uint8_t> rsa_sign(const std::vector<uint8_t>& data,
                               const std::vector<uint8_t>& private_key_der);
bool rsa_verify(const std::vector<uint8_t>& data,
                const std::vector<uint8_t>& signature,
                const std::vector<uint8_t>& public_key_der);

// ECDSA (КВАНТОВО-УЯЗВИМ)
struct EcKeyPair {
    std::vector<uint8_t> private_key_der;
    std::vector<uint8_t> public_key_der;
    std::string curve_name;  // "prime256v1", "secp384r1" и т.д.
};

// EC_KEY_new / EC_GROUP_new_by_curve_name — детектируется PQC-инструментом
EcKeyPair ec_generate_key(const std::string& curve = "prime256v1");

// ECDSA_sign / ECDSA_verify — УСТАРЕВШИЕ
std::vector<uint8_t> ecdsa_sign(const std::vector<uint8_t>& digest,
                                 const std::vector<uint8_t>& private_key_der);
bool ecdsa_verify(const std::vector<uint8_t>& digest,
                  const std::vector<uint8_t>& signature,
                  const std::vector<uint8_t>& public_key_der);

// EVP DigestSign (детектируется как EVP_DigestSignInit и т.д.)
std::vector<uint8_t> evp_digest_sign(const std::vector<uint8_t>& data,
                                      const std::vector<uint8_t>& private_key_der);
bool evp_digest_verify(const std::vector<uint8_t>& data,
                       const std::vector<uint8_t>& signature,
                       const std::vector<uint8_t>& public_key_der);

// AES-256-GCM (аутентифицированное шифрование, постквантово стойкий)
std::vector<uint8_t> aes256_gcm_encrypt(const std::vector<uint8_t>& plaintext,
                                         const std::vector<uint8_t>& key,
                                         const std::vector<uint8_t>& iv,
                                         const std::vector<uint8_t>& aad,
                                         std::vector<uint8_t>& tag_out);
std::vector<uint8_t> aes256_gcm_decrypt(const std::vector<uint8_t>& ciphertext,
                                         const std::vector<uint8_t>& key,
                                         const std::vector<uint8_t>& iv,
                                         const std::vector<uint8_t>& aad,
                                         const std::vector<uint8_t>& tag);

// SHA-256 / SHA-512 (постквантово стойкие при достаточной длине вывода)
std::vector<uint8_t> sha256(const std::vector<uint8_t>& data);
std::vector<uint8_t> sha512(const std::vector<uint8_t>& data);

// DH_generate_key / ECDH_compute_key — КВАНТОВО-УЯЗВИМЫ, детектируются
struct DhKeyExchange {
    std::vector<uint8_t> shared_secret;
    std::vector<uint8_t> public_value;
};
DhKeyExchange ecdh_key_exchange(const EcKeyPair& local,
                                 const std::vector<uint8_t>& remote_public_key);

} // namespace openssl

// Сравнение производительности ГОСТ vs классических алгоритмов (бенчмарк)
struct PerfResult {
    std::string algorithm;
    double ops_per_second;
    double bytes_per_second;
    size_t key_bits;
    bool quantum_safe;
};

std::vector<PerfResult> benchmark_all(size_t data_size_kb = 64,
                                      unsigned iterations = 100);

} // namespace gost