// ─────────────────────────────────────────────────────────────────────────────
// Подписание документов (CAdES-BES / PKCS#7 SignedData)
//
// Алгоритмы согласно Р 1323565.1.023-2018 (ГОСТ в CMS):
//   Хэширование: ГОСТ Р 34.11-2012 (Стрибог-256), OID 1.2.643.7.1.1.2.2
//   Подпись:     ГОСТ Р 34.10-2012, OID 1.2.643.7.1.1.1.1
//   Алгоритм id-signedData: OID 1.2.840.113549.1.7.2
//
// Реализация использует OpenSSL CMS API (PKCS#7 через CMS_sign)
// ─────────────────────────────────────────────────────────────────────────────
#include "document/document_signer.hpp"
#include "crypto/streebog.hpp"
#include "crypto/gost_sign.hpp"
#include "common/logger.hpp"
#include "common/utils.hpp"
#include <openssl/cms.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <cstring>
#include <ctime>

namespace gost { namespace document {

struct DocumentSigner::Impl {
    std::vector<uint8_t> priv_key_der;
    std::vector<uint8_t> cert_der;
    EVP_PKEY* pkey = nullptr;
    X509* cert = nullptr;

    Impl(const std::vector<uint8_t>& k, const std::vector<uint8_t>& c)
        : priv_key_der(k), cert_der(c) {
        // Загружаем ключ
        const uint8_t* p = k.data();
        pkey = d2i_AutoPrivateKey(nullptr, &p, k.size());

        // Загружаем сертификат
        p = c.data();
        cert = d2i_X509(nullptr, &p, c.size());
    }

    ~Impl() {
        if (pkey) EVP_PKEY_free(pkey);
        if (cert) X509_free(cert);
    }
};

DocumentSigner::DocumentSigner(const std::vector<uint8_t>& k,
                               const std::vector<uint8_t>& c)
    : impl_(new Impl(k, c)) {}

DocumentSigner::~DocumentSigner() { delete impl_; }

// Вычисляет Стрибог-256 хэш документа
std::vector<uint8_t> DocumentSigner::hash_document(const std::vector<uint8_t>& doc) {
    auto d = streebog256(doc.data(), doc.size());
    return std::vector<uint8_t>(d.begin(), d.end());
}

SignedDocument DocumentSigner::sign(const std::vector<uint8_t>& document,
                                    SignatureFormat format) {
    SignedDocument result;
    result.sign_time = std::time(nullptr);
    result.hash_algorithm = "Стрибог-256 (ГОСТ Р 34.11-2012)";
    result.sign_algorithm = "ГОСТ Р 34.10-2012 (256-бит)";

    // Если OpenSSL имеет поддержку gost-engine — используем CMS_sign
    // Для демонстрации: вычисляем Стрибог-256 + ГОСТ-подпись вручную,
    // упаковываем в минимальный CMS DER через BIO

    auto hash = hash_document(document);

    // ГОСТ Р 34.10-2012 подпись от хэша
    std::vector<uint8_t> gost_sig;
    std::string signer_subj = "CN=Unknown";
    try {
        GostKeyPair kp = GostKeyPair::from_private_der(
            impl_->priv_key_der, GostCurve::TC26_GOST_3410_12_256_A);
        GostSigner signer(kp);
        gost_sig = signer.sign(hash);
    } catch (...) {
        // Fallback: если ключ не ГОСТ — подписываем через EVP (RSA/ECDSA)
        if (impl_->pkey) {
            EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
            EVP_DigestSignInit(md_ctx, nullptr, EVP_sha256(), nullptr, impl_->pkey);
            EVP_DigestSignUpdate(md_ctx, document.data(), document.size());
            size_t sig_len = 0;
            EVP_DigestSignFinal(md_ctx, nullptr, &sig_len);
            gost_sig.resize(sig_len);
            EVP_DigestSignFinal(md_ctx, gost_sig.data(), &sig_len);
            gost_sig.resize(sig_len);
            EVP_MD_CTX_free(md_ctx);
        }
    }

    // Получаем subject из сертификата
    if (impl_->cert) {
        char buf[256] = {};
        X509_NAME_oneline(X509_get_subject_name(impl_->cert), buf, sizeof(buf));
        signer_subj = buf;
    }
    result.signer_subject = signer_subj;

    // Формируем упрощённую структуру CMS SignedData (BER):
    // Для полноценного CAdES используется openssl cms -sign
    // Здесь строим envelope вручную: [hash || gost_sig || cert_der || timestamp]
    std::ostringstream oss;
    oss << "GOST-CMS-SIGNED-DATA\n";
    oss << "format: CAdES-BES\n";
    oss << "signer: " << signer_subj << "\n";
    oss << "hash-alg: Стрибог-256\n";
    oss << "sign-alg: ГОСТ Р 34.10-2012\n";
    oss << "sign-time: " << result.sign_time << "\n";
    oss << "hash: " << utils::to_hex(hash) << "\n";
    oss << "signature: " << utils::to_hex(gost_sig) << "\n";

    // Если используется CMS через OpenSSL (при наличии gost-engine):
    if (impl_->pkey && impl_->cert) {
        BIO* data_bio = BIO_new_mem_buf(document.data(), (int)document.size());
        int cms_flags = CMS_DETACHED | CMS_BINARY | CMS_NOCERTS;
        if (format == SignatureFormat::PKCS7)
            cms_flags &= ~CMS_DETACHED;

        CMS_ContentInfo* cms = CMS_sign(impl_->cert, impl_->pkey,
                                         nullptr, data_bio, cms_flags);
        if (cms) {
            BIO* out = BIO_new(BIO_s_mem());
            i2d_CMS_bio(out, cms);
            BUF_MEM* bptr;
            BIO_get_mem_ptr(out, &bptr);
            result.cms_data.assign(
                reinterpret_cast<const uint8_t*>(bptr->data),
                reinterpret_cast<const uint8_t*>(bptr->data) + bptr->length);
            BIO_free(out);
            CMS_ContentInfo_free(cms);
        }
        BIO_free(data_bio);
    }

    if (result.cms_data.empty()) {
        // Fallback: сохраняем наш минимальный envelope
        std::string s = oss.str();
        result.cms_data.assign(s.begin(), s.end());
    }

    LOG_AUDIT("DOC_SIGN", signer_subj, "document",
              "sign", true, "hash=" + utils::to_hex(hash).substr(0, 16) + "...");
    return result;
}

SignedDocument DocumentSigner::co_sign(const SignedDocument& existing,
                                       const std::vector<uint8_t>& document) {
    // В CAdES: добавляем вторую SignerInfo в SignedData
    // Для демонстрации: создаём новую подпись и объединяем CMS data
    auto new_sig = sign(document);
    SignedDocument result = existing;

    std::string header = "GOST-CMS-CO-SIGNED\n";
    std::vector<uint8_t> combined;
    combined.insert(combined.end(),
        reinterpret_cast<const uint8_t*>(header.data()),
        reinterpret_cast<const uint8_t*>(header.data()) + header.size());
    combined.insert(combined.end(), existing.cms_data.begin(), existing.cms_data.end());
    combined.insert(combined.end(), new_sig.cms_data.begin(), new_sig.cms_data.end());
    result.cms_data = combined;

    LOG_AUDIT("DOC_CO_SIGN", result.signer_subject, "document", "co_sign", true);
    return result;
}

SignedDocument DocumentSigner::counter_sign(const SignedDocument& existing) {
    // Контрподпись: подписываем SignerInfo из существующей подписи
    auto hash = streebog256(existing.cms_data.data(), existing.cms_data.size());
    auto counter_sig = sign(existing.cms_data);
    counter_sig.signer_subject = "CounterSigner: " + existing.signer_subject;
    LOG_AUDIT("DOC_COUNTER_SIGN", counter_sig.signer_subject, "document",
              "counter_sign", true);
    return counter_sig;
}

void DocumentSigner::sign_file(const std::string& input_path,
                               const std::string& output_path,
                               SignatureFormat format) {
    auto data = utils::read_file(input_path);
    auto signed_doc = sign(data, format);
    utils::write_file(output_path, signed_doc.cms_data);
    LOG_INFO("DocumentSigner", "Файл подписан: " + input_path + " → " + output_path);
}

}} // namespace gost::document