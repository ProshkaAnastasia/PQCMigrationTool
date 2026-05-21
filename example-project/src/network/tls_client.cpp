// ─────────────────────────────────────────────────────────────────────────────
// TLS-клиент с mTLS и ГОСТ шифрсьютами (OpenSSL)
// ─────────────────────────────────────────────────────────────────────────────
#include "network/tls_client.hpp"
#include "common/logger.hpp"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <stdexcept>
#include <cstring>

namespace gost { namespace network {

struct TlsClient::Impl {
    Config cfg;
    SSL_CTX* ctx = nullptr;
    SSL* ssl = nullptr;
    int fd = -1;
    bool connected = false;

    Impl(const Config& c) : cfg(c) {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();

        ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) throw std::runtime_error("SSL_CTX_new (client) failed");

        SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);

        // Предпочтение ГОСТ шифрсьютов при наличии gost-engine
        if (cfg.prefer_gost_ciphers) {
            SSL_CTX_set_cipher_list(ctx,
                "GOST2012-GOST8912-GOST8912:GOST2012-NULL-GOST12:"
                "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384");
        }

        // Клиентский сертификат (для mTLS)
        if (!cfg.cert_file.empty()) {
            if (SSL_CTX_use_certificate_file(ctx, cfg.cert_file.c_str(), SSL_FILETYPE_PEM) != 1)
                throw std::runtime_error("TLS клиент: не удалось загрузить сертификат");
            if (SSL_CTX_use_PrivateKey_file(ctx, cfg.key_file.c_str(), SSL_FILETYPE_PEM) != 1)
                throw std::runtime_error("TLS клиент: не удалось загрузить ключ");
        }

        // Верификация сервера
        if (cfg.verify_server && !cfg.ca_cert_file.empty()) {
            SSL_CTX_load_verify_locations(ctx, cfg.ca_cert_file.c_str(), nullptr);
            SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
        } else if (!cfg.verify_server) {
            SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
        }
    }

    ~Impl() {
        if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
        if (ctx) SSL_CTX_free(ctx);
        if (fd >= 0) close(fd);
    }
};

TlsClient::TlsClient(const Config& cfg) : impl_(std::make_unique<Impl>(cfg)) {}
TlsClient::~TlsClient() = default;

bool TlsClient::connect(const std::string& host, uint16_t port) {
    // Резолвинг хоста
    struct addrinfo hints = {}, *res;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    std::string port_str = std::to_string(port);
    if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res) != 0)
        return false;

    impl_->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (impl_->fd < 0) { freeaddrinfo(res); return false; }

    // Таймаут подключения
    struct timeval tv = {impl_->cfg.timeout_sec, 0};
    setsockopt(impl_->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(impl_->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (::connect(impl_->fd, res->ai_addr, res->ai_addrlen) < 0) {
        freeaddrinfo(res);
        close(impl_->fd);
        impl_->fd = -1;
        return false;
    }
    freeaddrinfo(res);

    // TLS Handshake
    impl_->ssl = SSL_new(impl_->ctx);
    SSL_set_fd(impl_->ssl, impl_->fd);
    SSL_set_tlsext_host_name(impl_->ssl, host.c_str());

    if (SSL_connect(impl_->ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        return false;
    }

    impl_->connected = true;
    LOG_INFO("TLS-клиент", "Подключён к " + host + ":" + std::to_string(port) +
             " (" + SSL_get_version(impl_->ssl) + "/" +
             SSL_CIPHER_get_name(SSL_get_current_cipher(impl_->ssl)) + ")");
    return true;
}

void TlsClient::disconnect() {
    if (impl_->ssl) {
        SSL_shutdown(impl_->ssl);
        SSL_free(impl_->ssl);
        impl_->ssl = nullptr;
    }
    if (impl_->fd >= 0) {
        close(impl_->fd);
        impl_->fd = -1;
    }
    impl_->connected = false;
}

bool TlsClient::is_connected() const { return impl_->connected; }

std::string TlsClient::negotiated_cipher() const {
    if (!impl_->ssl) return "";
    return SSL_CIPHER_get_name(SSL_get_current_cipher(impl_->ssl));
}

std::string TlsClient::peer_cert_subject() const {
    if (!impl_->ssl) return "";
    X509* cert = SSL_get_peer_certificate(impl_->ssl);
    if (!cert) return "";
    char buf[256];
    X509_NAME_oneline(X509_get_subject_name(cert), buf, sizeof(buf));
    X509_free(cert);
    return std::string(buf);
}

std::string TlsClient::tls_version() const {
    if (!impl_->ssl) return "";
    return SSL_get_version(impl_->ssl);
}

ssize_t TlsClient::write(const void* data, size_t len) {
    if (!impl_->ssl) return -1;
    return SSL_write(impl_->ssl, data, (int)len);
}

ssize_t TlsClient::read(void* buf, size_t len) {
    if (!impl_->ssl) return -1;
    return SSL_read(impl_->ssl, buf, (int)len);
}

int TlsClient::fd() const { return impl_->fd; }

std::vector<uint8_t> TlsClient::read_all(size_t max_bytes) {
    std::vector<uint8_t> result;
    result.reserve(4096);
    uint8_t buf[4096];
    while (result.size() < max_bytes) {
        int n = SSL_read(impl_->ssl, buf, sizeof(buf));
        if (n <= 0) break;
        result.insert(result.end(), buf, buf + n);
    }
    return result;
}

}} // namespace gost::network