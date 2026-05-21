// ─────────────────────────────────────────────────────────────────────────────
// TLS-сервер с mTLS (mutual TLS) — OpenSSL + POSIX сокеты
// Поддержка ГОСТ шифрсьютов при наличии gost-engine для OpenSSL
// ─────────────────────────────────────────────────────────────────────────────
#include "network/tls_server.hpp"
#include "common/logger.hpp"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <atomic>
#include <thread>
#include <stdexcept>
#include <cstring>

namespace gost { namespace network {

struct TlsServer::Impl {
    Config cfg;
    SSL_CTX* ctx = nullptr;
    int server_fd = -1;
    std::atomic<bool> running{false};
    ConnectionHandler handler;

    Impl(const Config& c) : cfg(c) {
        // Инициализация OpenSSL
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();

        // Создание TLS контекста (TLS 1.3 — минимальная версия)
        ctx = SSL_CTX_new(TLS_server_method());
        if (!ctx) throw std::runtime_error("SSL_CTX_new failed");

        // TLS 1.3 минимум
        SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);

        // Если предпочитаем ГОСТ шифрсьюты — задаём приоритет
        // При наличии gost-engine: GOST2012-GOST8912-GOST8912 (Кузнечик + Стрибог)
        if (cfg.prefer_gost_ciphers) {
            SSL_CTX_set_cipher_list(ctx,
                "GOST2012-GOST8912-GOST8912:GOST2012-NULL-GOST12:"
                "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384");
        }

        // Загрузка сертификата сервера
        if (SSL_CTX_use_certificate_file(ctx, cfg.cert_file.c_str(), SSL_FILETYPE_PEM) != 1)
            throw std::runtime_error("Не удалось загрузить сертификат: " + cfg.cert_file);

        // Загрузка закрытого ключа
        if (SSL_CTX_use_PrivateKey_file(ctx, cfg.key_file.c_str(), SSL_FILETYPE_PEM) != 1)
            throw std::runtime_error("Не удалось загрузить ключ: " + cfg.key_file);

        if (!SSL_CTX_check_private_key(ctx))
            throw std::runtime_error("Сертификат и ключ не совпадают");

        // Загрузка CA для проверки клиентских сертификатов (mTLS)
        if (!cfg.ca_cert_file.empty()) {
            SSL_CTX_load_verify_locations(ctx, cfg.ca_cert_file.c_str(), nullptr);
            if (cfg.require_client_cert) {
                SSL_CTX_set_verify(ctx,
                    SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
            }
        }

        LOG_INFO("TLS-сервер", "Инициализирован, ожидание на " +
                 cfg.bind_addr + ":" + std::to_string(cfg.port));
    }

    ~Impl() {
        if (ctx) SSL_CTX_free(ctx);
        if (server_fd >= 0) close(server_fd);
    }
};

TlsServer::TlsServer(const Config& cfg) : impl_(std::make_unique<Impl>(cfg)) {}
TlsServer::~TlsServer() = default;

void TlsServer::set_connection_handler(ConnectionHandler h) {
    impl_->handler = std::move(h);
}

void TlsServer::start() {
    // Создание TCP сокета
    impl_->server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (impl_->server_fd < 0)
        throw std::runtime_error("socket() failed");

    int opt = 1;
    setsockopt(impl_->server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(impl_->cfg.port);
    inet_pton(AF_INET, impl_->cfg.bind_addr.c_str(), &addr.sin_addr);

    if (bind(impl_->server_fd, (sockaddr*)&addr, sizeof(addr)) < 0)
        throw std::runtime_error("bind() failed на порту " +
                                 std::to_string(impl_->cfg.port));

    listen(impl_->server_fd, impl_->cfg.backlog);
    impl_->running = true;

    LOG_INFO("TLS-сервер", "Прослушивание на порту " +
             std::to_string(impl_->cfg.port));

    while (impl_->running) {
        sockaddr_in client_addr = {};
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(impl_->server_fd, (sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) {
            if (!impl_->running) break;
            continue;
        }

        // TLS Handshake в отдельном потоке
        SSL_CTX* ctx = impl_->ctx;
        ConnectionHandler handler = impl_->handler;
        std::thread([client_fd, ctx, client_addr, handler]() {
            SSL* ssl = SSL_new(ctx);
            SSL_set_fd(ssl, client_fd);

            ClientInfo info;
            info.peer_addr = inet_ntoa(client_addr.sin_addr);
            info.peer_port = ntohs(client_addr.sin_port);

            if (SSL_accept(ssl) <= 0) {
                ERR_print_errors_fp(stderr);
                SSL_free(ssl);
                close(client_fd);
                return;
            }

            info.tls_version = SSL_get_version(ssl);
            const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl);
            if (cipher) info.cipher_suite = SSL_CIPHER_get_name(cipher);

            // Проверка клиентского сертификата
            X509* peer_cert = SSL_get_peer_certificate(ssl);
            if (peer_cert) {
                char buf[256];
                X509_NAME_oneline(X509_get_subject_name(peer_cert), buf, sizeof(buf));
                info.cert_subject = buf;
                info.authenticated = true;
                X509_free(peer_cert);
            }

            LOG_AUDIT("TLS_CONNECT", info.peer_addr, "сервер", "подключение", true,
                      info.cipher_suite);

            if (handler) handler(client_fd, info);

            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client_fd);
        }).detach();
    }
}

void TlsServer::stop() {
    impl_->running = false;
    if (impl_->server_fd >= 0) {
        shutdown(impl_->server_fd, SHUT_RDWR);
    }
}

bool TlsServer::is_running() const { return impl_->running; }

ssize_t TlsServer::tls_write(int ssl_fd, const void* data, size_t len) {
    return write(ssl_fd, data, len);
}

ssize_t TlsServer::tls_read(int ssl_fd, void* buf, size_t len) {
    return read(ssl_fd, buf, len);
}

}} // namespace gost::network