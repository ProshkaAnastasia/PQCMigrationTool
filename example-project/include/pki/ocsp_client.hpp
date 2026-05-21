#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// OCSP клиент — онлайн-проверка статуса сертификата
// Стандарты: RFC 6960 (OCSP), RFC 6961 (TLS OCSP Stapling)
// ─────────────────────────────────────────────────────────────────────────────
#include <string>
#include <vector>
#include <ctime>

namespace gost { namespace pki {

class Certificate;

enum class OcspStatus { GOOD, REVOKED, UNKNOWN };

struct OcspResponse {
    OcspStatus status;
    std::time_t this_update;
    std::time_t next_update;
    int revocation_reason;      // если REVOKED
    std::time_t revocation_time;// если REVOKED
    std::vector<uint8_t> raw;   // сырой OCSP-ответ для stapling
};

class OcspClient {
public:
    OcspClient();
    ~OcspClient();

    // Проверка статуса сертификата через HTTP/HTTPS
    OcspResponse check(const Certificate& cert,
                       const Certificate& issuer_cert,
                       const std::string& ocsp_url = "");

    // Верификация OCSP-ответа
    bool verify_response(const std::vector<uint8_t>& response,
                         const Certificate& issuer_cert);

    // Декодирование OCSP Stapling из TLS-соединения
    OcspStatus parse_stapled_response(const std::vector<uint8_t>& stapled);

private:
    struct Impl;
    Impl* impl_;
};

}} // namespace gost::pki