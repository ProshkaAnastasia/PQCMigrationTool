#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// TLS-клиент с поддержкой ГОСТ шифрсьютов и взаимной аутентификации (mTLS)
// ─────────────────────────────────────────────────────────────────────────────
#include <string>
#include <vector>
#include <memory>

namespace gost { namespace network {

class TlsClient {
public:
    struct Config {
        std::string cert_file;      // Клиентский сертификат
        std::string key_file;       // Закрытый ключ клиента
        std::string ca_cert_file;   // Сертификат УЦ для проверки сервера
        bool verify_server = true;  // Проверять сертификат сервера
        bool prefer_gost_ciphers = true;
        int timeout_sec = 30;
    };

    explicit TlsClient(const Config& cfg);
    ~TlsClient();

    // Подключение к серверу
    bool connect(const std::string& host, uint16_t port);
    void disconnect();
    bool is_connected() const;

    // Информация о соединении
    std::string negotiated_cipher() const;
    std::string peer_cert_subject() const;
    std::string tls_version() const;

    // Передача данных
    ssize_t write(const void* data, size_t len);
    ssize_t read(void* buf, size_t len);
    std::vector<uint8_t> read_all(size_t max_bytes = 65536);

    // Raw socket fd (используется с сырым протоколом до TLS-handshake)
    int fd() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}} // namespace gost::network