#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// Подписание документов (CAdES / PKCS#7 с ГОСТ Р 34.10-2012)
//
// Поддерживаемые форматы:
//   CAdES-BES   — базовая подпись (ГОСТ + Стрибог)
//   CAdES-T     — подпись с меткой времени
//   PKCS#7      — SignedData (RFC 5652)
//
// Стандарты:
//   ГОСТ Р 34.10-2012   — ЭП
//   ГОСТ Р 34.11-2012   — хэш (Стрибог)
//   Р 1323565.1.023-2018 — ГОСТ в CAdES
//   RFC 5652             — CMS SignedData
//   RFC 5751             — S/MIME (для email)
// ─────────────────────────────────────────────────────────────────────────────
#include <string>
#include <vector>
#include <ctime>

namespace gost { namespace document {

enum class SignatureFormat { CADES_BES, CADES_T, PKCS7 };

struct SignedDocument {
    std::vector<uint8_t> cms_data;  // DER-кодированный CMS SignedData
    std::time_t sign_time;
    std::string signer_subject;
    std::string hash_algorithm;     // "Стрибог-256" / "Стрибог-512"
    std::string sign_algorithm;     // "ГОСТ Р 34.10-2012 (256-бит)"
};

class DocumentSigner {
public:
    DocumentSigner(const std::vector<uint8_t>& private_key_der,
                   const std::vector<uint8_t>& cert_der);
    ~DocumentSigner();

    // Подписание документа (CAdES-BES)
    SignedDocument sign(const std::vector<uint8_t>& document,
                        SignatureFormat format = SignatureFormat::CADES_BES);

    // Добавление совместной подписи к уже подписанному документу
    SignedDocument co_sign(const SignedDocument& existing,
                           const std::vector<uint8_t>& document);

    // Добавление контрподписи (countersignature)
    SignedDocument counter_sign(const SignedDocument& existing);

    // Подписание файла
    void sign_file(const std::string& input_path,
                   const std::string& output_path,
                   SignatureFormat format = SignatureFormat::CADES_BES);

    // Хэш документа согласно ГОСТ Р 34.11-2012 (Стрибог-256)
    std::vector<uint8_t> hash_document(const std::vector<uint8_t>& document);

private:
    struct Impl;
    Impl* impl_;
};

}} // namespace gost::document