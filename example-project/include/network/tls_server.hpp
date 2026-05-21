#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// TLS-сервер с поддержкой ГОСТ шифрсьютов (OpenSSL)
//
// Поддерживаемые шифрсьюты (при наличии gost-engine):
//   GOST2012-GOST8912-GOST8912      — Кузнечик + Стрибог-256 (рекомендован)
//   GOST2012-NULL-GOST12            — только аутентификация
//   GOST2001-GOST89-GOST89          — ГОСТ 2001 (совместимость)
//
// В режиме без gost-engine использует TLS 1.3 с ECDHE+AES-256-GCM.
// ─────────────────────────────────────────────────────────────────────────────
#include <string>
#include <vector>
#include <functional>
#include <memory>

namespace gost { namespace network {

struct ClientInfo {
    std::string peer_addr;
    int peer_port;
    std::string tls_version;
    std::string cipher_suite;
    std::string cert_subject;    // если mutual TLS
    bool authenticated = false;
};

class TlsServer {
public:
    struct Config {
        std::string cert_file;           // PEM-сертификат сервера
        std::string key_file;            // PEM-закрытый ключ сервера
        std::string ca_cert_file;        // Сертификат УЦ для mTLS
        bool require_client_cert = true; // Обязательная аутентификация клиента
        std::string bind_addr = "0.0.0.0";
        uint16_t port = 8443;
        int backlog = 16;
        bool prefer_gost_ciphers = true; // Предпочтение ГОСТ шифрсьютов
    };

    using ConnectionHandler = std::function<void(int client_fd, const ClientInfo&)>;

    explicit TlsServer(const Config& cfg);
    ~TlsServer();

    void set_connection_handler(ConnectionHandler handler);
    void start();
    void stop();
    bool is_running() const;

    // Отправить/получить данные по TLS-соединению
    static ssize_t tls_write(int ssl_fd, const void* data, size_t len);
    static ssize_t tls_read(int ssl_fd, void* buf, size_t len);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}} // namespace gost::network