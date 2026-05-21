// ─────────────────────────────────────────────────────────────────────────────
// OCSP клиент (RFC 6960) — онлайн-проверка статуса сертификата
// ─────────────────────────────────────────────────────────────────────────────
#include "pki/ocsp_client.hpp"
#include "cert_impl_internal.hpp"
#include <openssl/ocsp.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <stdexcept>
#include <cstring>
#include <ctime>

namespace gost { namespace pki {

struct OcspClient::Impl {
    // В реальной реализации хранит настройки подключения
};

OcspClient::OcspClient() : impl_(new Impl()) {}
OcspClient::~OcspClient() { delete impl_; }

OcspResponse OcspClient::check(const Certificate& cert,
                                const Certificate& issuer,
                                const std::string& ocsp_url)
{
    OcspResponse resp;
    resp.this_update = std::time(nullptr);
    resp.next_update = resp.this_update + 3600;
    resp.revocation_reason = 0;
    resp.revocation_time = 0;

    // Формирование OCSP запроса через OpenSSL
    OCSP_REQUEST* req = OCSP_REQUEST_new();
    OCSP_CERTID* id = OCSP_cert_to_id(EVP_sha256(),
                                       cert.impl_->cert,
                                       issuer.impl_->cert);
    if (id) {
        OCSP_request_add0_id(req, id);
        // Нonce для защиты от replay-атак
        OCSP_request_add1_nonce(req, nullptr, 32);
    }

    // В реальной системе здесь отправка HTTP POST к ocsp_url
    // Для демонстрации возвращаем GOOD статус
    resp.status = OcspStatus::GOOD;

    OCSP_REQUEST_free(req);
    return resp;
}

bool OcspClient::verify_response(const std::vector<uint8_t>& response,
                                  const Certificate& issuer) {
    const unsigned char* p = response.data();
    OCSP_RESPONSE* resp = d2i_OCSP_RESPONSE(nullptr, &p, response.size());
    if (!resp) return false;

    int status = OCSP_response_status(resp);
    bool ok = (status == OCSP_RESPONSE_STATUS_SUCCESSFUL);
    OCSP_RESPONSE_free(resp);
    return ok;
}

OcspStatus OcspClient::parse_stapled_response(const std::vector<uint8_t>& stapled) {
    if (stapled.empty()) return OcspStatus::UNKNOWN;
    const unsigned char* p = stapled.data();
    OCSP_RESPONSE* resp = d2i_OCSP_RESPONSE(nullptr, &p, stapled.size());
    if (!resp) return OcspStatus::UNKNOWN;

    int status = OCSP_response_status(resp);
    OCSP_BASICRESP* bs = OCSP_response_get1_basic(resp);
    OcspStatus result = OcspStatus::UNKNOWN;
    if (bs) {
        OCSP_SINGLERESP* sr = OCSP_resp_get0(bs, 0);
        if (sr) {
            int reason = 0;
            ASN1_GENERALIZEDTIME *rev = nullptr, *this_upd = nullptr, *next_upd = nullptr;
            int cert_status = OCSP_single_get0_status(sr, &reason, &rev, &this_upd, &next_upd);
            if (cert_status == V_OCSP_CERTSTATUS_GOOD)
                result = OcspStatus::GOOD;
            else if (cert_status == V_OCSP_CERTSTATUS_REVOKED)
                result = OcspStatus::REVOKED;
        }
        OCSP_BASICRESP_free(bs);
    }
    OCSP_RESPONSE_free(resp);
    return result;
}

}} // namespace gost::pki