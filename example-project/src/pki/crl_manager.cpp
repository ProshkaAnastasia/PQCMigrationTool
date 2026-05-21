// ─────────────────────────────────────────────────────────────────────────────
// Управление CRL (Certificate Revocation List) через OpenSSL
// ─────────────────────────────────────────────────────────────────────────────
#include "pki/crl_manager.hpp"
#include "cert_impl_internal.hpp"
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <stdexcept>
#include <unordered_map>
#include <cstring>
#include <ctime>

namespace gost { namespace pki {

struct CrlManager::Impl {
    X509_CRL* crl = nullptr;
    std::unordered_map<std::string, RevokedEntry> revoked_map;

    void build_index() {
        revoked_map.clear();
        if (!crl) return;
        STACK_OF(X509_REVOKED)* rev = X509_CRL_get_REVOKED(crl);
        int n = sk_X509_REVOKED_num(rev);
        for (int i = 0; i < n; i++) {
            X509_REVOKED* r = sk_X509_REVOKED_value(rev, i);
            const ASN1_INTEGER* sn = X509_REVOKED_get0_serialNumber(r);
            BIGNUM* bn = ASN1_INTEGER_to_BN(sn, nullptr);
            char* hex = BN_bn2hex(bn);
            RevokedEntry entry;
            entry.serial_hex = hex;
            entry.revocation_time = 0;
            const ASN1_TIME* rt = X509_REVOKED_get0_revocationDate(r);
            if (rt) {
                struct tm tm = {};
                ASN1_TIME_to_tm(rt, &tm);
                entry.revocation_time = mktime(&tm);
            }
            revoked_map[entry.serial_hex] = entry;
            OPENSSL_free(hex);
            BN_free(bn);
        }
    }

    ~Impl() { if (crl) X509_CRL_free(crl); }
};

CrlManager::CrlManager() : impl_(std::make_unique<Impl>()) {}
CrlManager::~CrlManager() = default;

void CrlManager::load_from_file(const std::string& path) {
    BIO* bio = BIO_new_file(path.c_str(), "r");
    if (!bio) throw std::runtime_error("CRL: не удалось открыть файл " + path);
    if (impl_->crl) X509_CRL_free(impl_->crl);
    impl_->crl = PEM_read_bio_X509_CRL(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!impl_->crl) {
        // Попробуем DER
        bio = BIO_new_file(path.c_str(), "rb");
        impl_->crl = d2i_X509_CRL_bio(bio, nullptr);
        BIO_free(bio);
    }
    if (!impl_->crl) throw std::runtime_error("CRL: не удалось разобрать " + path);
    impl_->build_index();
}

void CrlManager::load_from_pem(const std::string& pem) {
    BIO* bio = BIO_new_mem_buf(pem.data(), (int)pem.size());
    if (impl_->crl) X509_CRL_free(impl_->crl);
    impl_->crl = PEM_read_bio_X509_CRL(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!impl_->crl) throw std::runtime_error("CRL: ошибка разбора PEM");
    impl_->build_index();
}

void CrlManager::load_from_der(const std::vector<uint8_t>& der) {
    const unsigned char* p = der.data();
    if (impl_->crl) X509_CRL_free(impl_->crl);
    impl_->crl = d2i_X509_CRL(nullptr, &p, der.size());
    if (!impl_->crl) throw std::runtime_error("CRL: ошибка разбора DER");
    impl_->build_index();
}

bool CrlManager::is_revoked(const Certificate& cert) const {
    return is_revoked(const_cast<Certificate&>(cert).serial_hex());
}

bool CrlManager::is_revoked(const std::string& serial_hex) const {
    return impl_->revoked_map.count(serial_hex) > 0;
}

const RevokedEntry* CrlManager::get_revocation_info(const std::string& serial_hex) const {
    auto it = impl_->revoked_map.find(serial_hex);
    if (it == impl_->revoked_map.end()) return nullptr;
    return &it->second;
}

std::string CrlManager::issuer() const {
    if (!impl_->crl) return "";
    char buf[512];
    X509_NAME_oneline(X509_CRL_get_issuer(impl_->crl), buf, sizeof(buf));
    return std::string(buf);
}

std::time_t CrlManager::this_update() const {
    if (!impl_->crl) return 0;
    const ASN1_TIME* t = X509_CRL_get0_lastUpdate(impl_->crl);
    struct tm tm = {};
    ASN1_TIME_to_tm(t, &tm);
    return mktime(&tm);
}

std::time_t CrlManager::next_update() const {
    if (!impl_->crl) return 0;
    const ASN1_TIME* t = X509_CRL_get0_nextUpdate(impl_->crl);
    if (!t) return 0;
    struct tm tm = {};
    ASN1_TIME_to_tm(t, &tm);
    return mktime(&tm);
}

bool CrlManager::is_expired() const {
    return next_update() > 0 && std::time(nullptr) > next_update();
}

size_t CrlManager::revoked_count() const {
    return impl_->revoked_map.size();
}

std::string CrlManager::signature_algorithm() const {
    if (!impl_->crl) return "";
    char buf[256] = {};
    const X509_ALGOR* alg;
    X509_CRL_get0_signature(impl_->crl, nullptr, &alg);
    OBJ_obj2txt(buf, sizeof(buf), alg->algorithm, 1);
    return std::string(buf);
}

bool CrlManager::verify_signature(const Certificate& ca_cert) const {
    if (!impl_->crl) return false;
    EVP_PKEY* pkey = X509_get_pubkey(ca_cert.impl_->cert);
    int ok = X509_CRL_verify(impl_->crl, pkey);
    EVP_PKEY_free(pkey);
    return ok == 1;
}

// ── Создание CRL с ГОСТ подписью ─────────────────────────────────────────────

std::vector<uint8_t> CrlManager::create_gost_crl(
    const Certificate& ca_cert,
    const std::vector<uint8_t>& ca_key_der,
    const std::vector<RevokedEntry>& revoked,
    int validity_days)
{
    X509_CRL* crl = X509_CRL_new();
    X509_CRL_set_version(crl, 1);  // v2
    X509_CRL_set_issuer_name(crl, X509_get_subject_name(ca_cert.impl_->cert));
    ASN1_TIME* last_upd = X509_gmtime_adj(nullptr, 0);
    X509_CRL_set1_lastUpdate(crl, last_upd);
    ASN1_TIME_free(last_upd);
    ASN1_TIME* next_upd = X509_gmtime_adj(nullptr, (long)validity_days * 86400);
    X509_CRL_set1_nextUpdate(crl, next_upd);
    ASN1_TIME_free(next_upd);

    // Добавление отозванных сертификатов
    for (const auto& entry : revoked) {
        X509_REVOKED* rev = X509_REVOKED_new();
        BIGNUM* bn = nullptr;
        BN_hex2bn(&bn, entry.serial_hex.c_str());
        ASN1_INTEGER* sn = BN_to_ASN1_INTEGER(bn, nullptr);
        X509_REVOKED_set_serialNumber(rev, sn);
        ASN1_INTEGER_free(sn);
        BN_free(bn);
        ASN1_TIME* rt = ASN1_TIME_new();
        ASN1_TIME_set(rt, entry.revocation_time);
        X509_REVOKED_set_revocationDate(rev, rt);
        ASN1_TIME_free(rt);
        X509_CRL_add0_revoked(crl, rev);
    }
    X509_CRL_sort(crl);

    const unsigned char* p = ca_key_der.data();
    EVP_PKEY* pkey = d2i_AutoPrivateKey(nullptr, &p, ca_key_der.size());
    X509_CRL_sign(crl, pkey, EVP_sha256());
    EVP_PKEY_free(pkey);

    unsigned char* buf = nullptr;
    int len = i2d_X509_CRL(crl, &buf);
    std::vector<uint8_t> out(buf, buf + len);
    OPENSSL_free(buf);
    X509_CRL_free(crl);
    return out;
}

// ── CrlCache ──────────────────────────────────────────────────────────────────

struct CrlCache::Impl {
    std::string cache_dir;
    std::unordered_map<std::string, std::unique_ptr<CrlManager>> cache;
};

CrlCache::CrlCache(const std::string& cache_dir) : impl_(std::make_unique<Impl>()) {
    impl_->cache_dir = cache_dir;
}
CrlCache::~CrlCache() = default;

const CrlManager& CrlCache::get_crl(const std::string& url) {
    auto it = impl_->cache.find(url);
    if (it != impl_->cache.end() && !it->second->is_expired()) {
        return *it->second;
    }
    // В реальной системе здесь HTTP-запрос к URL
    // Для демонстрации возвращаем пустой CRL
    impl_->cache[url] = std::make_unique<CrlManager>();
    return *impl_->cache[url];
}

bool CrlCache::check_revocation(const Certificate& cert) {
    // В реальной системе здесь получаем URL из CDP extension сертификата
    return false;  // Stub для демонстрации
}

}} // namespace gost::pki