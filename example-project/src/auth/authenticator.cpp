// ─────────────────────────────────────────────────────────────────────────────
// Challenge-response аутентификация с ГОСТ Р 34.10-2012 подписями
// ─────────────────────────────────────────────────────────────────────────────
#include "auth/authenticator.hpp"
#include "crypto/gost_sign.hpp"
#include "crypto/gost_prng.hpp"
#include "pki/cert_manager.hpp"
#include "common/logger.hpp"
#include "common/utils.hpp"
#include <stdexcept>

namespace gost { namespace auth {

struct Authenticator::Impl {
    std::string ca_cert_file;
    pki::Certificate ca_cert;

    explicit Impl(const std::string& ca_file)
        : ca_cert_file(ca_file), ca_cert(pki::Certificate::from_file(ca_file)) {}
};

Authenticator::Authenticator(const std::string& ca_cert_file)
    : impl_(new Impl(ca_cert_file)) {}
Authenticator::~Authenticator() { delete impl_; }

// ── Challenge: 32 случайных байта (ГПСЧ ГОСТ Р 34.20-2012) ──────────────────

std::vector<uint8_t> Authenticator::generate_challenge() {
    // Используем ГОСТ ГПСЧ на основе Кузнечика (CTR_DRBG)
    return global_prng().generate(32);
}

// ── Подписание challenge закрытым ключом ГОСТ Р 34.10-2012 ───────────────────

std::vector<uint8_t> Authenticator::sign_challenge(
    const std::vector<uint8_t>& challenge,
    const std::vector<uint8_t>& private_key_der)
{
    // В реальной ГОСТ-системе:
    // 1. Хэшируем challenge алгоритмом Стрибог-256 (ГОСТ Р 34.11-2012)
    // 2. Подписываем хэш алгоритмом ГОСТ Р 34.10-2012
    //    (gost_ec_sign — функция gost-engine OpenSSL)

    // Загружаем ключ для ГОСТ Р 34.10-2012
    GostKeyPair kp = GostKeyPair::from_private_der(private_key_der,
                                                    GostCurve::TC26_GOST_3410_12_256_A);
    GostSigner signer(kp);
    auto sig = signer.sign(challenge);

    LOG_AUDIT("AUTH_SIGN", "клиент", "challenge", "ГОСТ Р 34.10-2012", true,
              "размер подписи: " + std::to_string(sig.size()));
    return sig;
}

// ── Проверка подписи клиента ──────────────────────────────────────────────────

bool Authenticator::verify_response(
    const std::vector<uint8_t>& challenge,
    const std::vector<uint8_t>& signature,
    const std::vector<uint8_t>& client_cert_der)
{
    if (!validate_client_cert(client_cert_der)) {
        LOG_AUDIT("AUTH_VERIFY", "сервер", "клиент", "проверка_сертификата",
                  false, "сертификат отозван или не доверенный");
        return false;
    }

    // Извлекаем открытый ключ из сертификата клиента
    pki::Certificate client_cert = pki::Certificate::from_der(client_cert_der);
    auto pub_key_der = client_cert.public_key_der();

    // Проверяем ГОСТ подпись (ECDSA_do_verify через OpenSSL EC)
    GostVerifier verifier(pub_key_der, GostCurve::TC26_GOST_3410_12_256_A);
    bool ok = verifier.verify(challenge, signature);

    LOG_AUDIT("AUTH_VERIFY", client_cert.subject(), "challenge",
              "ГОСТ Р 34.10-2012", ok,
              ok ? "успешно" : "подпись неверна");
    return ok;
}

// ── Валидация клиентского сертификата ─────────────────────────────────────────

bool Authenticator::validate_client_cert(const std::vector<uint8_t>& client_cert_der) {
    try {
        pki::Certificate client_cert = pki::Certificate::from_der(client_cert_der);
        if (client_cert.is_expired()) {
            LOG_WARN("AUTH", "Сертификат клиента просрочен: " + client_cert.subject());
            return false;
        }
        bool chain_ok = pki::verify_cert_chain(client_cert, impl_->ca_cert);
        if (!chain_ok) {
            LOG_WARN("AUTH", "Цепочка сертификатов не прошла проверку");
        }
        return chain_ok;
    } catch (const std::exception& e) {
        LOG_ERROR("AUTH", std::string("Ошибка проверки сертификата: ") + e.what());
        return false;
    }
}

}} // namespace gost::auth