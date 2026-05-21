#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// Аутентификация на основе ГОСТ Р 34.10-2012 (challenge-response)
// ─────────────────────────────────────────────────────────────────────────────
#include <string>
#include <vector>
#include <cstdint>

namespace gost { namespace auth {

// Challenge-response аутентификация с ГОСТ-подписью
class Authenticator {
public:
    explicit Authenticator(const std::string& ca_cert_file);
    ~Authenticator();

    // Сторона сервера: генерация challenge (32 случайных байта)
    std::vector<uint8_t> generate_challenge();

    // Сторона сервера: проверка ответа клиента
    // Клиент подписывает challenge закрытым ключом ГОСТ Р 34.10-2012
    bool verify_response(const std::vector<uint8_t>& challenge,
                         const std::vector<uint8_t>& signature,
                         const std::vector<uint8_t>& client_cert_der);

    // Сторона клиента: подписание challenge
    std::vector<uint8_t> sign_challenge(
        const std::vector<uint8_t>& challenge,
        const std::vector<uint8_t>& private_key_der
    );

    // Проверка сертификата клиента (цепочка до УЦ + проверка отзыва)
    bool validate_client_cert(const std::vector<uint8_t>& client_cert_der);

private:
    struct Impl;
    Impl* impl_;
};

}} // namespace gost::auth