#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// Проверка подписей документов (CAdES / PKCS#7) с ГОСТ алгоритмами
// ─────────────────────────────────────────────────────────────────────────────
#include <string>
#include <vector>
#include <ctime>

namespace gost { namespace document {

struct VerificationResult {
    bool valid;
    std::string signer_subject;
    std::string signer_cert_fingerprint;  // Стрибог-256
    std::time_t sign_time;
    std::string hash_algorithm;
    std::string sign_algorithm;
    std::string failure_reason;           // Если !valid
    bool cert_chain_valid;
    bool cert_not_revoked;
    bool timestamp_valid;
};

class DocumentVerifier {
public:
    explicit DocumentVerifier(const std::string& ca_cert_file);
    ~DocumentVerifier();

    // Проверка CAdES/PKCS#7 подписи
    VerificationResult verify(const std::vector<uint8_t>& signed_data,
                              const std::vector<uint8_t>& original_document = {});

    // Проверка подписи файла
    VerificationResult verify_file(const std::string& signed_file,
                                   const std::string& original_file = "");

    // Список всех подписей в документе (для совместных подписей)
    std::vector<VerificationResult> verify_all(const std::vector<uint8_t>& signed_data);

    // Извлечение сертификата подписанта
    std::vector<uint8_t> extract_signer_cert(const std::vector<uint8_t>& signed_data);

private:
    struct Impl;
    Impl* impl_;
};

}} // namespace gost::document