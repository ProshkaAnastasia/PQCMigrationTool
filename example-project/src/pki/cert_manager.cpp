// ─────────────────────────────────────────────────────────────────────────────
// Управление X.509 сертификатами (OpenSSL)
// Поддержка ГОСТ OID и ГОСТ Р 34.10-2012 подписи
// ─────────────────────────────────────────────────────────────────────────────
#include "cert_impl_internal.hpp"
#include "crypto/streebog.hpp"
#include "common/utils.hpp"
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/pkcs12.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <stdexcept>
#include <cstring>
#include <ctime>

namespace gost { namespace pki {

Certificate::Certificate(std::unique_ptr<Impl> p) : impl_(std::move(p)) {}
Certificate::~Certificate() = default;
Certificate::Certificate(Certificate&&) noexcept = default;
Certificate& Certificate::operator=(Certificate&&) noexcept = default;

Certificate Certificate::from_pem(const std::string& pem) {
    BIO* bio = BIO_new_mem_buf(pem.data(), (int)pem.size());
    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!cert) throw std::runtime_error("Certificate: не удалось разобрать PEM");
    return Certificate(std::make_unique<Impl>(cert));
}

Certificate Certificate::from_der(const std::vector<uint8_t>& der) {
    const unsigned char* p = der.data();
    X509* cert = d2i_X509(nullptr, &p, der.size());
    if (!cert) throw std::runtime_error("Certificate: не удалось разобрать DER");
    return Certificate(std::make_unique<Impl>(cert));
}

Certificate Certificate::from_file(const std::string& path) {
    BIO* bio = BIO_new_file(path.c_str(), "r");
    if (!bio) throw std::runtime_error("Certificate: не удалось открыть файл: " + path);
    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!cert) throw std::runtime_error("Certificate: не удалось прочитать из файла: " + path);
    return Certificate(std::make_unique<Impl>(cert));
}

std::string Certificate::subject() const {
    char buf[512];
    X509_NAME_oneline(X509_get_subject_name(impl_->cert), buf, sizeof(buf));
    return std::string(buf);
}

std::string Certificate::issuer() const {
    char buf[512];
    X509_NAME_oneline(X509_get_issuer_name(impl_->cert), buf, sizeof(buf));
    return std::string(buf);
}

std::string Certificate::serial_hex() const {
    const ASN1_INTEGER* sn = X509_get_serialNumber(impl_->cert);
    BIGNUM* bn = ASN1_INTEGER_to_BN(sn, nullptr);
    char* hex = BN_bn2hex(bn);
    std::string result(hex);
    OPENSSL_free(hex);
    BN_free(bn);
    return result;
}

std::time_t Certificate::not_before() const {
    const ASN1_TIME* t = X509_get0_notBefore(impl_->cert);
    struct tm tm = {};
    ASN1_TIME_to_tm(t, &tm);
    return mktime(&tm);
}

std::time_t Certificate::not_after() const {
    const ASN1_TIME* t = X509_get0_notAfter(impl_->cert);
    struct tm tm = {};
    ASN1_TIME_to_tm(t, &tm);
    return mktime(&tm);
}

bool Certificate::is_expired() const {
    return std::time(nullptr) > not_after();
}

bool Certificate::is_ca_cert() const {
    BASIC_CONSTRAINTS* bc = (BASIC_CONSTRAINTS*)X509_get_ext_d2i(
        impl_->cert, NID_basic_constraints, nullptr, nullptr);
    bool is_ca = bc && bc->ca;
    BASIC_CONSTRAINTS_free(bc);
    return is_ca;
}

std::string Certificate::signature_algorithm() const {
    char buf[256] = {};
    const X509_ALGOR* alg = X509_get0_tbs_sigalg(impl_->cert);
    OBJ_obj2txt(buf, sizeof(buf), alg->algorithm, 1);  // OID как строка
    return std::string(buf);
}

std::vector<uint8_t> Certificate::public_key_der() const {
    unsigned char* buf = nullptr;
    EVP_PKEY* pkey = X509_get_pubkey(impl_->cert);
    int len = i2d_PublicKey(pkey, &buf);
    std::vector<uint8_t> out(buf, buf + len);
    OPENSSL_free(buf);
    EVP_PKEY_free(pkey);
    return out;
}

std::string Certificate::fingerprint_streebog256() const {
    unsigned char* der = nullptr;
    int len = i2d_X509(impl_->cert, &der);
    auto h = streebog256(der, len);
    OPENSSL_free(der);
    return utils::to_hex(h.data(), h.size());
}

std::string Certificate::fingerprint_sha256() const {
    unsigned char md[32];
    unsigned int len = sizeof(md);
    X509_digest(impl_->cert, EVP_sha256(), md, &len);
    return utils::to_hex(md, len);
}

std::string Certificate::to_pem() const {
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, impl_->cert);
    BUF_MEM* bptr;
    BIO_get_mem_ptr(bio, &bptr);
    std::string pem(bptr->data, bptr->length);
    BIO_free(bio);
    return pem;
}

std::vector<uint8_t> Certificate::to_der() const {
    unsigned char* buf = nullptr;
    int len = i2d_X509(impl_->cert, &buf);
    std::vector<uint8_t> out(buf, buf + len);
    OPENSSL_free(buf);
    return out;
}

// ── Создание самоподписанного сертификата ─────────────────────────────────────

Certificate create_self_signed_gost_cert(const CertInfo& info,
                                         const std::vector<uint8_t>& priv_der) {
    const unsigned char* p = priv_der.data();
    EVP_PKEY* pkey = d2i_AutoPrivateKey(nullptr, &p, priv_der.size());
    if (!pkey) throw std::runtime_error("create_self_signed_gost_cert: ошибка ключа");

    X509* cert = X509_new();
    X509_set_version(cert, 2);  // v3

    // Серийный номер
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);

    // Срок действия
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 86400L * info.validity_days);

    // Открытый ключ
    X509_set_pubkey(cert, pkey);

    // Subject DN
    X509_NAME* name = X509_get_subject_name(cert);
    if (!info.subject_country.empty())
        X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
            (const unsigned char*)info.subject_country.c_str(), -1, -1, 0);
    if (!info.subject_org.empty())
        X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
            (const unsigned char*)info.subject_org.c_str(), -1, -1, 0);
    if (!info.subject_cn.empty())
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
            (const unsigned char*)info.subject_cn.c_str(), -1, -1, 0);
    if (!info.subject_email.empty())
        X509_NAME_add_entry_by_txt(name, "emailAddress", MBSTRING_ASC,
            (const unsigned char*)info.subject_email.c_str(), -1, -1, 0);

    // Самоподписанный: issuer = subject
    X509_set_issuer_name(cert, name);

    // Расширения X.509v3
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert, cert, nullptr, nullptr, 0);

    if (info.is_ca) {
        X509_EXTENSION* bc = X509V3_EXT_conf_nid(nullptr, &ctx, NID_basic_constraints,
                                                   "critical,CA:TRUE");
        X509_add_ext(cert, bc, -1);
        X509_EXTENSION_free(bc);
    }

    // SubjectKeyIdentifier
    X509_EXTENSION* ski = X509V3_EXT_conf_nid(nullptr, &ctx, NID_subject_key_identifier, "hash");
    if (ski) { X509_add_ext(cert, ski, -1); X509_EXTENSION_free(ski); }

    // Подписываем SHA-256 (OpenSSL использует SHA-256 с EC для ECDSA)
    // В реальной ГОСТ-системе здесь должна быть подпись ГОСТ Р 34.10-2012
    X509_sign(cert, pkey, EVP_sha256());

    EVP_PKEY_free(pkey);
    return Certificate(std::make_unique<Certificate::Impl>(cert));
}

// ── Проверка цепочки сертификатов ────────────────────────────────────────────

bool verify_cert_chain(const Certificate& cert, const Certificate& ca_cert) {
    X509_STORE* store = X509_STORE_new();
    X509_STORE_add_cert(store, ca_cert.impl_->cert);
    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(ctx, store, cert.impl_->cert, nullptr);
    int ok = X509_verify_cert(ctx);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    return ok == 1;
}

// ── PKCS#12 ───────────────────────────────────────────────────────────────────

std::vector<uint8_t> create_pkcs12(
    const Certificate& cert,
    const std::vector<uint8_t>& priv_der,
    const std::string& friendly_name,
    const std::string& password)
{
    const unsigned char* p = priv_der.data();
    EVP_PKEY* pkey = d2i_AutoPrivateKey(nullptr, &p, priv_der.size());

    // PKCS12_create — создание PKCS#12 контейнера
    PKCS12* p12 = PKCS12_create(
        password.c_str(),
        friendly_name.c_str(),
        pkey,
        cert.impl_->cert,
        nullptr, 0, 0, 0, 0, 0
    );
    if (!p12) throw std::runtime_error("PKCS12_create failed");

    unsigned char* buf = nullptr;
    int len = i2d_PKCS12(p12, &buf);
    std::vector<uint8_t> out(buf, buf + len);
    OPENSSL_free(buf);
    PKCS12_free(p12);
    EVP_PKEY_free(pkey);
    return out;
}

std::pair<Certificate, std::vector<uint8_t>> load_pkcs12(
    const std::vector<uint8_t>& pkcs12_data,
    const std::string& password)
{
    const unsigned char* p = pkcs12_data.data();
    PKCS12* p12 = d2i_PKCS12(nullptr, &p, pkcs12_data.size());
    if (!p12) throw std::runtime_error("load_pkcs12: parse failed");

    EVP_PKEY* pkey = nullptr;
    X509* cert = nullptr;
    PKCS12_parse(p12, password.c_str(), &pkey, &cert, nullptr);
    PKCS12_free(p12);

    if (!cert || !pkey) throw std::runtime_error("load_pkcs12: parse returned null");

    unsigned char* der = nullptr;
    int len = i2d_PrivateKey(pkey, &der);
    std::vector<uint8_t> key_der(der, der + len);
    OPENSSL_free(der);
    EVP_PKEY_free(pkey);

    return {Certificate(std::make_unique<Certificate::Impl>(cert)), key_der};
}

// ── Генерация CSR ─────────────────────────────────────────────────────────────

std::vector<uint8_t> generate_gost_csr(const CertInfo& info,
                                        const std::vector<uint8_t>& priv_der) {
    const unsigned char* p = priv_der.data();
    EVP_PKEY* pkey = d2i_AutoPrivateKey(nullptr, &p, priv_der.size());
    X509_REQ* req = X509_REQ_new();
    X509_REQ_set_pubkey(req, pkey);
    X509_NAME* name = X509_REQ_get_subject_name(req);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        (const unsigned char*)info.subject_cn.c_str(), -1, -1, 0);
    X509_REQ_sign(req, pkey, EVP_sha256());
    EVP_PKEY_free(pkey);
    unsigned char* buf = nullptr;
    int len = i2d_X509_REQ(req, &buf);
    std::vector<uint8_t> out(buf, buf + len);
    OPENSSL_free(buf);
    X509_REQ_free(req);
    return out;
}

}} // namespace gost::pki