#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// Управление сессиями с ГОСТ-токенами (аналог JWT, подпись ГОСТ Р 34.10-2012)
// ─────────────────────────────────────────────────────────────────────────────
#include <string>
#include <vector>
#include <cstdint>
#include <optional>
#include <ctime>

namespace gost { namespace auth {

struct Session {
    std::string id;               // UUID сессии
    std::string user_id;          // Идентификатор пользователя
    std::string cert_fingerprint; // Отпечаток сертификата (Стрибог-256)
    std::time_t created_at;
    std::time_t expires_at;
    bool is_valid() const;
};

// ГОСТ-токен (аналог JWT с подписью ГОСТ Р 34.10-2012)
// Формат: base64(header) . base64(payload) . base64(подпись ГОСТ)
class SessionManager {
public:
    explicit SessionManager(const std::vector<uint8_t>& signing_key_der,
                            const std::vector<uint8_t>& verify_key_der,
                            int session_ttl_sec = 3600);
    ~SessionManager();

    // Создание новой сессии
    Session create_session(const std::string& user_id,
                           const std::string& cert_fingerprint);

    // Выдача токена (подписан ГОСТ Р 34.10-2012 через Стрибог-256)
    std::string issue_token(const Session& session);

    // Проверка и декодирование токена
    std::optional<Session> verify_token(const std::string& token);

    // Инвалидация сессии
    void invalidate(const std::string& session_id);

    // Очистка просроченных сессий
    size_t cleanup_expired();

    size_t active_sessions() const;

private:
    struct Impl;
    Impl* impl_;
};

}} // namespace gost::auth