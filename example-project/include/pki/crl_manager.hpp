#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// Управление списками отзыва сертификатов (CRL — Certificate Revocation List)
// Стандарты: RFC 5280, RFC 5480 (ECDSA CRL), RFC 7091 (ГОСТ в PKIX)
// ─────────────────────────────────────────────────────────────────────────────
#include <string>
#include <vector>
#include <memory>
#include <ctime>

namespace gost { namespace pki {

class Certificate;

struct RevokedEntry {
    std::string serial_hex;      // Серийный номер отозванного сертификата
    std::time_t revocation_time; // Время отзыва
    int reason_code;             // RFC 5280: 0=unspecified, 1=keyCompromise, ...
    std::string reason_str;
};

class CrlManager {
public:
    CrlManager();
    ~CrlManager();

    // Загрузка CRL из файла или данных
    void load_from_file(const std::string& path);
    void load_from_pem(const std::string& pem);
    void load_from_der(const std::vector<uint8_t>& der);

    // Проверка отзыва сертификата
    bool is_revoked(const Certificate& cert) const;
    bool is_revoked(const std::string& serial_hex) const;
    const RevokedEntry* get_revocation_info(const std::string& serial_hex) const;

    // Информация о CRL
    std::string issuer() const;
    std::time_t this_update() const;
    std::time_t next_update() const;
    bool is_expired() const;
    size_t revoked_count() const;
    std::string signature_algorithm() const;

    // Верификация подписи CRL сертификатом УЦ
    bool verify_signature(const Certificate& ca_cert) const;

    // Создание CRL (для УЦ) с ГОСТ-подписью
    static std::vector<uint8_t> create_gost_crl(
        const Certificate& ca_cert,
        const std::vector<uint8_t>& ca_key_der,
        const std::vector<RevokedEntry>& revoked,
        int validity_days = 7
    );

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Кэш CRL с периодическим обновлением
class CrlCache {
public:
    explicit CrlCache(const std::string& cache_dir = "/tmp/crl_cache");
    ~CrlCache();

    // Получить (или обновить) CRL для указанного URL
    const CrlManager& get_crl(const std::string& distribution_point_url);

    // Проверка с автоматическим получением CRL
    bool check_revocation(const Certificate& cert);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}} // namespace gost::pki