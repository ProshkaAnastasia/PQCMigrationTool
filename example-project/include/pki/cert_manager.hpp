#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// Управление X.509 сертификатами с поддержкой ГОСТ OID
// Стандарты: RFC 5280, RFC 7091 (ГОСТ в PKIX), RFC 4491 (ГОСТ в CMS/PKIX)
// ─────────────────────────────────────────────────────────────────────────────
#include <string>
#include <vector>
#include <memory>
#include <ctime>

namespace gost { namespace pki {

// Идентификаторы ГОСТ OID для X.509
namespace oids {
    constexpr const char* GOST_R3410_2012_256   = "1.2.643.7.1.1.1.1"; // ЭП-256
    constexpr const char* GOST_R3410_2012_512   = "1.2.643.7.1.1.1.2"; // ЭП-512
    constexpr const char* STREEBOG_256          = "1.2.643.7.1.1.2.2"; // Стрибог-256
    constexpr const char* STREEBOG_512          = "1.2.643.7.1.1.2.3"; // Стрибог-512
    constexpr const char* SIGN_WITH_STREEBOG_256 = "1.2.643.7.1.1.3.2"; // ЭП-256 со Стрибог-256
    constexpr const char* SIGN_WITH_STREEBOG_512 = "1.2.643.7.1.1.3.3"; // ЭП-512 со Стрибог-512
    constexpr const char* TC26_PARAM_256_A      = "1.2.643.7.1.2.1.1.1"; // Кривая 256-A
    constexpr const char* TC26_PARAM_512_A      = "1.2.643.7.1.2.1.2.1"; // Кривая 512-A
    constexpr const char* OGRN                  = "1.2.643.100.1";  // ОГРН
    constexpr const char* SNILS                 = "1.2.643.100.3";  // СНИЛС
    constexpr const char* INN                   = "1.2.643.3.131.1.1"; // ИНН
}

struct CertInfo {
    std::string subject_cn;        // Common Name
    std::string subject_org;       // Organisation
    std::string subject_country;   // Country (RU)
    std::string subject_email;
    std::string issuer_cn;
    int validity_days = 365;
    bool is_ca = false;
    std::string serial;            // hex serial number
    std::string key_usage;         // digitalSignature, keyEncipherment, etc.
};

// Загрузка и разбор X.509 сертификата
class Certificate {
public:
    static Certificate from_pem(const std::string& pem);
    static Certificate from_der(const std::vector<uint8_t>& der);
    static Certificate from_file(const std::string& path);

    std::string subject() const;
    std::string issuer() const;
    std::string serial_hex() const;
    std::time_t not_before() const;
    std::time_t not_after() const;
    bool is_expired() const;
    bool is_ca_cert() const;
    std::string signature_algorithm() const;  // OID строкой
    std::vector<uint8_t> public_key_der() const;
    std::string fingerprint_streebog256() const;  // ГОСТ Р 34.11-2012
    std::string fingerprint_sha256() const;        // SHA-256

    std::string to_pem() const;
    std::vector<uint8_t> to_der() const;

    ~Certificate();
    Certificate(Certificate&&) noexcept;
    Certificate& operator=(Certificate&&) noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    explicit Certificate(std::unique_ptr<Impl>);

    // Доступ к внутреннему OpenSSL X509* для PKI-функций и клиентов
    friend Certificate create_self_signed_gost_cert(const CertInfo&,
                                                     const std::vector<uint8_t>&);
    friend Certificate sign_csr_with_gost(const std::vector<uint8_t>&, const Certificate&,
                                          const std::vector<uint8_t>&, const CertInfo&);
    friend bool verify_cert_chain(const Certificate&, const Certificate&);
    friend std::vector<uint8_t> create_pkcs12(const Certificate&,
                                               const std::vector<uint8_t>&,
                                               const std::string&, const std::string&);
    friend std::pair<Certificate, std::vector<uint8_t>> load_pkcs12(
        const std::vector<uint8_t>&, const std::string&);
    friend class CrlManager;
    friend class OcspClient;
};

// Самоподписанный ГОСТ-сертификат (УЦ или конечный)
Certificate create_self_signed_gost_cert(const CertInfo& info,
                                         const std::vector<uint8_t>& private_key_der);

// Подписание CSR центром сертификации
Certificate sign_csr_with_gost(const std::vector<uint8_t>& csr_der,
                                const Certificate& ca_cert,
                                const std::vector<uint8_t>& ca_private_key_der,
                                const CertInfo& override_info = {});

// Генерация CSR (Certificate Signing Request)
std::vector<uint8_t> generate_gost_csr(
    const CertInfo& info,
    const std::vector<uint8_t>& private_key_der
);

// Верификация цепочки сертификатов с ГОСТ-подписью
bool verify_cert_chain(const Certificate& cert,
                        const Certificate& ca_cert);

// PKCS#12 — контейнер для ключа и сертификата
std::vector<uint8_t> create_pkcs12(
    const Certificate& cert,
    const std::vector<uint8_t>& private_key_der,
    const std::string& friendly_name,
    const std::string& password
);

std::pair<Certificate, std::vector<uint8_t>> load_pkcs12(
    const std::vector<uint8_t>& pkcs12_data,
    const std::string& password
);

}} // namespace gost::pki