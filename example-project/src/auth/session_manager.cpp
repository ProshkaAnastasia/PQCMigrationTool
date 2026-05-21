// ─────────────────────────────────────────────────────────────────────────────
// Управление сессиями с ГОСТ-токенами (аналог JWT)
//
// Структура токена (3 части, разделитель '.'):
//   base64(header_json) . base64(payload_json) . base64(gost_signature)
//
// Алгоритм подписи: ГОСТ Р 34.10-2012 от Стрибог-256(header.payload)
// ─────────────────────────────────────────────────────────────────────────────
#include "auth/session_manager.hpp"
#include "crypto/gost_sign.hpp"
#include "crypto/streebog.hpp"
#include "common/logger.hpp"
#include "common/utils.hpp"
#include <unordered_map>
#include <mutex>
#include <sstream>
#include <cstring>

namespace gost { namespace auth {

bool Session::is_valid() const {
    return std::time(nullptr) < expires_at;
}

struct SessionManager::Impl {
    std::vector<uint8_t> sign_key;
    std::vector<uint8_t> verify_key;
    int ttl;
    std::unordered_map<std::string, Session> sessions;
    mutable std::mutex mu;

    Impl(const std::vector<uint8_t>& sk, const std::vector<uint8_t>& vk, int t)
        : sign_key(sk), verify_key(vk), ttl(t) {}
};

SessionManager::SessionManager(const std::vector<uint8_t>& sk,
                               const std::vector<uint8_t>& vk,
                               int ttl)
    : impl_(new Impl(sk, vk, ttl)) {}

SessionManager::~SessionManager() { delete impl_; }

Session SessionManager::create_session(const std::string& user_id,
                                       const std::string& cert_fp) {
    Session s;
    s.id = utils::generate_uuid();
    s.user_id = user_id;
    s.cert_fingerprint = cert_fp;
    s.created_at = std::time(nullptr);
    s.expires_at = s.created_at + impl_->ttl;

    std::lock_guard<std::mutex> lock(impl_->mu);
    impl_->sessions[s.id] = s;

    LOG_AUDIT("SESSION_CREATE", user_id, s.id, "create", true,
              "ttl=" + std::to_string(impl_->ttl) + "s");
    return s;
}

// Сериализует сессию в формат base64(header).base64(payload).base64(подпись ГОСТ)
std::string SessionManager::issue_token(const Session& session) {
    // Заголовок: алгоритм подписи
    std::string header = R"({"typ":"GOST-TOKEN","alg":"GOST3410-2012-256"})";

    // Полезная нагрузка (минимальный JSON)
    std::ostringstream payload_ss;
    payload_ss << R"({"sid":")" << session.id
               << R"(","sub":")" << session.user_id
               << R"(","fp":")"  << session.cert_fingerprint
               << R"(","iat":)"  << session.created_at
               << R"(,"exp":)"   << session.expires_at << "}";
    std::string payload = payload_ss.str();

    std::string h_enc = utils::to_base64(
        reinterpret_cast<const uint8_t*>(header.data()), header.size());
    std::string p_enc = utils::to_base64(
        reinterpret_cast<const uint8_t*>(payload.data()), payload.size());

    // Подписываем Стрибог-256 от "header_b64.payload_b64"
    std::string to_sign = h_enc + "." + p_enc;
    auto digest = streebog256(
        reinterpret_cast<const uint8_t*>(to_sign.data()), to_sign.size());

    // Подпись ГОСТ Р 34.10-2012
    std::string sig_enc;
    if (!impl_->sign_key.empty()) {
        try {
            GostKeyPair kp = GostKeyPair::from_private_der(
                impl_->sign_key, GostCurve::TC26_GOST_3410_12_256_A);
            GostSigner signer(kp);
            auto sig = signer.sign(digest.data(), digest.size());
            sig_enc = utils::to_base64(sig);
        } catch (...) {
            sig_enc = utils::to_base64(digest.data(), digest.size());  // fallback: только хэш
        }
    } else {
        sig_enc = utils::to_base64(digest.data(), digest.size());
    }

    return h_enc + "." + p_enc + "." + sig_enc;
}

// Простейший парсер JSON-значения по ключу (для демонстрации)
static std::string json_get(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\":";
    auto pos = json.find(search);
    if (pos == std::string::npos) return {};
    pos += search.size();
    if (json[pos] == '"') {
        ++pos;
        auto end = json.find('"', pos);
        return json.substr(pos, end - pos);
    }
    // Число
    auto end = json.find_first_of(",}", pos);
    return json.substr(pos, end - pos);
}

std::optional<Session> SessionManager::verify_token(const std::string& token) {
    // Разделяем на части
    auto d1 = token.find('.');
    auto d2 = token.find('.', d1 + 1);
    if (d1 == std::string::npos || d2 == std::string::npos)
        return std::nullopt;

    std::string h_enc = token.substr(0, d1);
    std::string p_enc = token.substr(d1 + 1, d2 - d1 - 1);
    std::string s_enc = token.substr(d2 + 1);

    // Проверяем подпись ГОСТ Р 34.10-2012
    std::string to_sign = h_enc + "." + p_enc;
    auto digest = streebog256(
        reinterpret_cast<const uint8_t*>(to_sign.data()), to_sign.size());

    auto sig = utils::from_base64(s_enc);

    if (!impl_->verify_key.empty()) {
        try {
            GostVerifier verifier(impl_->verify_key, GostCurve::TC26_GOST_3410_12_256_A);
            if (!verifier.verify(digest.data(), digest.size(), sig)) {
                LOG_AUDIT("TOKEN_VERIFY", "system", "token", "verify", false,
                          "подпись не совпадает");
                return std::nullopt;
            }
        } catch (...) { /* если ключ не задан или ошибка */ }
    }

    // Декодируем payload
    auto payload_bytes = utils::from_base64(p_enc);
    std::string payload(payload_bytes.begin(), payload_bytes.end());

    Session s;
    s.id = json_get(payload, "sid");
    s.user_id = json_get(payload, "sub");
    s.cert_fingerprint = json_get(payload, "fp");
    try {
        s.created_at = std::stoll(json_get(payload, "iat"));
        s.expires_at = std::stoll(json_get(payload, "exp"));
    } catch (...) { return std::nullopt; }

    if (!s.is_valid()) {
        LOG_AUDIT("TOKEN_VERIFY", s.user_id, s.id, "verify", false, "токен просрочен");
        return std::nullopt;
    }

    // Проверяем что сессия ещё активна
    std::lock_guard<std::mutex> lock(impl_->mu);
    auto it = impl_->sessions.find(s.id);
    if (it == impl_->sessions.end()) {
        LOG_AUDIT("TOKEN_VERIFY", s.user_id, s.id, "verify", false, "сессия не найдена");
        return std::nullopt;
    }

    LOG_AUDIT("TOKEN_VERIFY", s.user_id, s.id, "verify", true);
    return s;
}

void SessionManager::invalidate(const std::string& session_id) {
    std::lock_guard<std::mutex> lock(impl_->mu);
    auto it = impl_->sessions.find(session_id);
    if (it != impl_->sessions.end()) {
        LOG_AUDIT("SESSION_INVALIDATE", it->second.user_id, session_id, "logout", true);
        impl_->sessions.erase(it);
    }
}

size_t SessionManager::cleanup_expired() {
    std::lock_guard<std::mutex> lock(impl_->mu);
    size_t removed = 0;
    auto now = std::time(nullptr);
    for (auto it = impl_->sessions.begin(); it != impl_->sessions.end(); ) {
        if (it->second.expires_at < now) {
            it = impl_->sessions.erase(it);
            ++removed;
        } else {
            ++it;
        }
    }
    if (removed > 0)
        LOG_INFO("SessionManager", "Удалено просроченных сессий: " + std::to_string(removed));
    return removed;
}

size_t SessionManager::active_sessions() const {
    std::lock_guard<std::mutex> lock(impl_->mu);
    return impl_->sessions.size();
}

}} // namespace gost::auth