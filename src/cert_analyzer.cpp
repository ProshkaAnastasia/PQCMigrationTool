#include "pqc/cert_analyzer.hpp"
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <fstream>
#include <filesystem>
#include <iostream>
#include <algorithm>
#include <cstring>
#include <ctime>
#include <set>

namespace pqc {
std::string cert_quantum_risk_str(CertQuantumRisk r)
{
    switch (r) {
        case CertQuantumRisk::HIGH:
            return "high";
        case CertQuantumRisk::MEDIUM:
            return "medium";
        case CertQuantumRisk::LOW:
            return "low";
        default:
            return "unknown";
    }
}
static std::string bio_to_string(BIO* bio)
{
    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(bio, &bptr);
    if (!bptr || !bptr->data)
        return "";
    return std::string(bptr->data, bptr->length);
}
static std::string asn1_time_to_str(const ASN1_TIME* t)
{
    if (!t)
        return "";
    BIO* bio = BIO_new(BIO_s_mem());
    ASN1_TIME_print(bio, t);
    auto s = bio_to_string(bio);
    BIO_free(bio);
    return s;
}
CertQuantumRisk CertAnalyzer::assess_algorithm(const std::string& alg, int key_bits)
{
    std::string a = alg;
    std::transform(a.begin(), a.end(), a.begin(), ::tolower);
    if (a.find("rsa") != std::string::npos)
        return CertQuantumRisk::HIGH;
    if (a.find("ecdsa") != std::string::npos)
        return CertQuantumRisk::HIGH;
    if (a.find("ecdh") != std::string::npos)
        return CertQuantumRisk::HIGH;
    if (a.find("dsa") != std::string::npos)
        return CertQuantumRisk::HIGH;
    if (a.find("ec") != std::string::npos)
        return CertQuantumRisk::HIGH;
    if (a.find("ed25519") != std::string::npos)
        return CertQuantumRisk::HIGH;
    if (a.find("ed448") != std::string::npos)
        return CertQuantumRisk::HIGH;
    if (a.find("gost") != std::string::npos)
        return CertQuantumRisk::HIGH;
    if (a.find("md5") != std::string::npos)
        return CertQuantumRisk::HIGH;
    if (a.find("sha1") != std::string::npos || a.find("sha-1") != std::string::npos)
        return CertQuantumRisk::MEDIUM;
    if (a.find("sha256") != std::string::npos || a.find("sha-256") != std::string::npos) {
        if (key_bits > 0 && key_bits < 256)
            return CertQuantumRisk::MEDIUM;
        return CertQuantumRisk::LOW;
    }
    if (a.find("sha384") != std::string::npos || a.find("sha512") != std::string::npos)
        return CertQuantumRisk::LOW;
    return CertQuantumRisk::UNKNOWN;
}
double CertAnalyzer::compute_cert_risk(CertQuantumRisk qr, int key_bits, bool expired,
                                       const std::string& alg)
{
    double s = (qr == CertQuantumRisk::HIGH     ? 9.0
                : qr == CertQuantumRisk::MEDIUM ? 5.5
                : qr == CertQuantumRisk::LOW    ? 2.0
                                                : 3.0);
    std::string a = alg;
    std::transform(a.begin(), a.end(), a.begin(), ::tolower);
    if (qr == CertQuantumRisk::HIGH && a.find("rsa") != std::string::npos && key_bits > 0 &&
        key_bits < 2048)
        s += 0.5;
    if (expired)
        s = std::max(0.0, s - 1.0);
    return std::min(10.0, s);
}
static void fill_info(X509* x509, CertInfo& info)
{
    // Subject & Issuer
    BIO* sbio = BIO_new(BIO_s_mem());
    X509_NAME_print_ex(sbio, X509_get_subject_name(x509), 0, XN_FLAG_ONELINE);
    info.subject = bio_to_string(sbio);
    BIO_free(sbio);
    BIO* ibio = BIO_new(BIO_s_mem());
    X509_NAME_print_ex(ibio, X509_get_issuer_name(x509), 0, XN_FLAG_ONELINE);
    info.issuer = bio_to_string(ibio);
    BIO_free(ibio);
    info.is_self_signed = (info.subject == info.issuer);
    // Serial
    ASN1_INTEGER* sn = X509_get_serialNumber(x509);
    if (sn) {
        BIGNUM* bn = ASN1_INTEGER_to_BN(sn, nullptr);
        if (bn) {
            char* h = BN_bn2hex(bn);
            if (h) {
                info.serial_number = h;
                OPENSSL_free(h);
            }
            BN_free(bn);
        }
    }
    // Validity
    info.not_before = asn1_time_to_str(X509_get0_notBefore(x509));
    info.not_after = asn1_time_to_str(X509_get0_notAfter(x509));
    // Expiry check
    int day, sec;
    ASN1_TIME_diff(&day, &sec, X509_get0_notAfter(x509), nullptr);
    info.is_expired = (day < 0 || sec < 0);
    // Signature algorithm
    const X509_ALGOR* salg = nullptr;
    X509_get0_signature(nullptr, &salg, x509);
    if (salg) {
        BIO* ab = BIO_new(BIO_s_mem());
        X509_signature_print(ab, salg, nullptr);
        info.sig_algorithm = bio_to_string(ab);
        BIO_free(ab);
        // also get OID string
        BIO* oid_bio = BIO_new(BIO_s_mem());
        i2a_ASN1_OBJECT(oid_bio, salg->algorithm);
        info.sig_algorithm = bio_to_string(oid_bio);
        BIO_free(oid_bio);
    }
    // Public key
    EVP_PKEY* pkey = X509_get0_pubkey(x509);
    if (pkey) {
        info.key_size_bits = EVP_PKEY_bits(pkey);
        int bid = EVP_PKEY_base_id(pkey);
        switch (bid) {
            case EVP_PKEY_RSA:
                info.public_key_algorithm = "RSA";
                break;
            case EVP_PKEY_EC:
                info.public_key_algorithm = "EC";
                break;
            case EVP_PKEY_DSA:
                info.public_key_algorithm = "DSA";
                break;
            case EVP_PKEY_DH:
                info.public_key_algorithm = "DH";
                break;
            case EVP_PKEY_ED25519:
                info.public_key_algorithm = "Ed25519";
                break;
            case EVP_PKEY_ED448:
                info.public_key_algorithm = "Ed448";
                break;
            default:
                info.public_key_algorithm = "Unknown(" + std::to_string(bid) + ")";
                break;
        }
    }
    // Risk assessment
    std::string combined = info.public_key_algorithm + " " + info.sig_algorithm;
    info.quantum_risk = CertAnalyzer::assess_algorithm(combined, info.key_size_bits);
    info.risk_score = CertAnalyzer::compute_cert_risk(info.quantum_risk, info.key_size_bits,
                                                      info.is_expired, combined);
    // Risk explanation
    switch (info.quantum_risk) {
        case CertQuantumRisk::HIGH:
            info.risk_explanation = info.public_key_algorithm +
                                    " keys are broken by Shor's algorithm. "
                                    "Replace with ML-DSA or SLH-DSA certificate (FIPS 204/205).";
            info.tc26_note =
                "ТК 26: алгоритмы на основе ЭЦП/ECDSA подлежат замене в переходный период";
            break;
        case CertQuantumRisk::MEDIUM:
            info.risk_explanation =
                "SHA-1 or weak hash; Grover's reduces security. Upgrade to SHA-256+.";
            info.tc26_note = "ТК 26: применение SHA-1 не допускается; рекомендован Стрибог-256";
            break;
        case CertQuantumRisk::LOW:
            info.risk_explanation = "Algorithm appears quantum-safe with current parameters.";
            info.tc26_note = "";
            break;
        default:
            break;
    }
}
std::vector<CertInfo> CertAnalyzer::analyze_file(const std::string& fp) const
{
    std::vector<CertInfo> infos;
    // Try PEM (may contain chain)
    FILE* f = std::fopen(fp.c_str(), "r");
    if (!f)
        return infos;
    X509* x509 = nullptr;
    while ((x509 = PEM_read_X509(f, nullptr, nullptr, nullptr)) != nullptr) {
        CertInfo ci;
        ci.file_path = fp;
        fill_info(x509, ci);
        X509_free(x509);
        infos.push_back(ci);
    }
    if (infos.empty()) {
        std::rewind(f);
        x509 = d2i_X509_fp(f, nullptr);
        if (x509) {
            CertInfo ci;
            ci.file_path = fp;
            fill_info(x509, ci);
            X509_free(x509);
            infos.push_back(ci);
        }
    }
    std::fclose(f);
    return infos;
}
std::vector<CertInfo> CertAnalyzer::analyze(const std::string& path) const
{
    std::vector<CertInfo> all;
    std::error_code ec;
    if (std::filesystem::is_directory(path, ec)) {
        static const std::set<std::string> ext = {".pem", ".crt", ".cer", ".der", ".p7b"};
        for (auto& e : std::filesystem::recursive_directory_iterator(
                 path, std::filesystem::directory_options::skip_permission_denied, ec)) {
            if (!e.is_regular_file())
                continue;
            if (!ext.count(e.path().extension().string()))
                continue;
            auto r = analyze_file(e.path().string());
            all.insert(all.end(), r.begin(), r.end());
        }
    } else {
        all = analyze_file(path);
    }
    return all;
}
nlohmann::json CertInfo::to_json() const
{
    return {{"file_path", file_path},
            {"subject", subject},
            {"issuer", issuer},
            {"serial_number", serial_number},
            {"not_before", not_before},
            {"not_after", not_after},
            {"sig_algorithm", sig_algorithm},
            {"public_key_algorithm", public_key_algorithm},
            {"key_size_bits", key_size_bits},
            {"quantum_risk", cert_quantum_risk_str(quantum_risk)},
            {"risk_score", risk_score},
            {"risk_explanation", risk_explanation},
            {"tc26_note", tc26_note},
            {"is_expired", is_expired},
            {"is_self_signed", is_self_signed}};
}
}  // namespace pqc
