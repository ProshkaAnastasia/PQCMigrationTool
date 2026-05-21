/**
 * @file server.cpp
 * @brief TCP-сервер с ГОСТ-криптографией
 *
 * ИСПОЛЬЗОВАНИЕ СТАНДАРТОВ:
 * ─────────────────────────────────────────────────────────────────────────
 * [ГОСТ 34.10-2018]
 *   • Генерация серверной ключевой пары подписи
 *   • Подпись ServerHello (аутентификация сервера)
 *   • Верификация подписи ClientFinish (аутентификация клиента)
 *
 * [VKO ГОСТ Р 34.10-2012]
 *   • Генерация серверной VKO-ключевой пары (paramset XA)
 *   • Приём UKM от клиента (или генерация своего)
 *   • Выработка сессионного ключа: deriveSharedKey(serverVKO, clientVKO, UKM)
 *
 * [ГОСТ 34.11-2018]
 *   • hash256() для формирования данных подписи
 *   • hmac256() для контроля целостности зашифрованных сообщений
 *   • Неявно: внутри EVP_DigestSign* для ЭЦП [ГОСТ 34.10-2018]
 *
 * [ГОСТ 34.12-2018] + [ГОСТ 34.13-2018]
 *   • kuznyechikDecryptCTR() — расшифровка сообщения клиента
 *   • kuznyechikEncryptCTR() — шифрование ответа сервера
 *   • magmaEncryptCTR() — дополнительная демонстрация Магма CTR
 * ─────────────────────────────────────────────────────────────────────────
 */

#include "gost_utils.hpp"
#include "protocol.hpp"

#include <iostream>
#include <string>
#include <sstream>
#include <stdexcept>
#include <cstring>
#include <thread>
#include <csignal>

// POSIX сокеты
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

// ─── Глобальные ключи сервера ────────────────────────────────────────────────
static GostSign::KeyPair g_server_sign_kp; // ГОСТ 34.10-2018
static GostSign::KeyPair g_server_vko_kp;  // VKO ГОСТ Р 34.10-2012

// ─── Сетевые утилиты ─────────────────────────────────────────────────────────
static bool sendAll(int fd, const std::string& data) {
    uint32_t len = htonl(static_cast<uint32_t>(data.size()));
    if (send(fd, &len, 4, 0) != 4) return false;
    size_t sent = 0;
    while (sent < data.size()) {
        ssize_t n = send(fd, data.data() + sent, data.size() - sent, 0);
        if (n <= 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

static std::string recvAll(int fd) {
    uint32_t net_len = 0;
    if (recv(fd, &net_len, 4, MSG_WAITALL) != 4) return "";
    uint32_t len = ntohl(net_len);
    if (len == 0 || len > 1024 * 1024) return "";
    std::string buf(len, '\0');
    size_t recvd = 0;
    while (recvd < len) {
        ssize_t n = recv(fd, &buf[recvd], len - recvd, 0);
        if (n <= 0) return "";
        recvd += static_cast<size_t>(n);
    }
    return buf;
}

// ─── Обработка одного клиента ────────────────────────────────────────────────
static void handleClient(int client_fd, const std::string& client_addr) {
    std::cout << "\n[SERVER] Новое подключение от " << client_addr << "\n";

    try {
        // ════════════════════════════════════════════════════════════════════
        // ШАГ 1: Получить ClientHello
        // ════════════════════════════════════════════════════════════════════
        std::string raw = recvAll(client_fd);
        if (raw.empty()) throw std::runtime_error("Пустой ClientHello");

        ClientHello ch = Proto::parseClientHello(raw);
        std::cout << "[SERVER] ClientHello получен\n";
        std::cout << "         nonce: " << ch.nonce_hex.substr(0, 16) << "...\n";

        // Десериализуем публичные ключи клиента
        // [ГОСТ 34.10-2018] — ключ проверки подписей клиента
        auto client_sign_pub = GostSign::pubkeyFromPem(ch.sign_pubkey_pem);
        // [VKO ГОСТ Р 34.10-2012] — ключ клиента для выработки сессионного ключа
        auto client_vko_pub  = GostSign::pubkeyFromPem(ch.vko_pubkey_pem);

        // ════════════════════════════════════════════════════════════════════
        // ШАГ 2: VKO — выработка сессионного ключа
        //        [VKO ГОСТ Р 34.10-2012]
        // ════════════════════════════════════════════════════════════════════
        // Генерируем UKM (8 байт) — User Keying Material
        Bytes ukm = GostCipher::randomBytes(8);

        std::cout << "[SERVER] VKO: выработка сессионного ключа...\n";
        // [VKO ГОСТ Р 34.10-2012] Вырабатываем общий ключ
        Bytes session_key = GostVKO::deriveSharedKey(
            g_server_vko_kp.pkey.get(),
            client_vko_pub.get(),
            ukm
        );

        // Ключ сессии расширяем до 32 байт (если нужно) через Стрибог
        // [ГОСТ 34.11-2018] hash256 для стандартизации длины ключа
        if (session_key.size() != 32) {
            session_key = GostHash::hash256(session_key);
        }
        std::cout << "[SERVER] Сессионный ключ: " << Utils::toHex(session_key).substr(0, 16) << "...\n";

        // ════════════════════════════════════════════════════════════════════
        // ШАГ 3: Формирование ServerHello с ЭЦП сервера
        //        [ГОСТ 34.10-2018]
        // ════════════════════════════════════════════════════════════════════
        Bytes server_nonce = GostCipher::randomBytes(32);

        // Данные для подписи: server_vko_pubkey || ukm || client_nonce
        // [ГОСТ 34.11-2018] Хэшируем данные перед подписью
        std::string sign_src = GostSign::pubkeyToPem(g_server_vko_kp.pkey.get())
                             + Utils::toHex(ukm)
                             + ch.nonce_hex;
        Bytes sign_data(sign_src.begin(), sign_src.end());

        // [ГОСТ 34.10-2018] Подписываем данные серверным ключом
        Bytes server_sig = GostSign::sign(g_server_sign_kp.pkey.get(), sign_data);
        std::cout << "[SERVER] ЭЦП ServerHello сформирована (ГОСТ 34.10-2018)\n";

        // Формируем ServerHello
        ServerHello sh;
        sh.sign_pubkey_pem  = GostSign::pubkeyToPem(g_server_sign_kp.pkey.get());
        sh.vko_pubkey_pem   = GostSign::pubkeyToPem(g_server_vko_kp.pkey.get());
        sh.ukm_hex          = Utils::toHex(ukm);
        sh.server_nonce_hex = Utils::toHex(server_nonce);
        sh.signature_hex    = Utils::toHex(server_sig);

        if (!sendAll(client_fd, Proto::serialize(sh)))
            throw std::runtime_error("Ошибка отправки ServerHello");
        std::cout << "[SERVER] ServerHello отправлен\n";

        // ════════════════════════════════════════════════════════════════════
        // ШАГ 4: Получить ClientFinish
        // ════════════════════════════════════════════════════════════════════
        raw = recvAll(client_fd);
        if (raw.empty()) throw std::runtime_error("Пустой ClientFinish");
        ClientFinish cf = Proto::parseClientFinish(raw);
        std::cout << "[SERVER] ClientFinish получен\n";

        // [ГОСТ 34.10-2018] Верифицируем подпись клиента
        std::string client_sign_src = sh.server_nonce_hex + "CLIENT_AUTHENTICATED";
        Bytes client_sign_data(client_sign_src.begin(), client_sign_src.end());
        Bytes client_sig = Utils::fromHex(cf.client_signature_hex);

        bool sig_ok = GostSign::verify(client_sign_pub.get(), client_sign_data, client_sig);
        if (!sig_ok) throw std::runtime_error("Верификация ЭЦП клиента ПРОВАЛЕНА [ГОСТ 34.10-2018]");
        std::cout << "[SERVER] ЭЦП клиента верифицирована (ГОСТ 34.10-2018) ✓\n";

        // Расшифровываем сообщение клиента
        Bytes iv          = Utils::fromHex(cf.iv_hex);
        Bytes ciphertext  = Utils::fromHex(cf.ciphertext_hex);
        Bytes recv_hmac   = Utils::fromHex(cf.hmac_hex);

        // [ГОСТ 34.11-2018] Проверка HMAC целостности шифртекста
        Bytes calc_hmac = GostHash::hmac256(session_key, ciphertext);
        if (calc_hmac != recv_hmac) throw std::runtime_error("HMAC не совпадает [ГОСТ 34.11-2018]");
        std::cout << "[SERVER] HMAC шифртекста проверен (ГОСТ 34.11-2018) ✓\n";

        // [ГОСТ 34.12-2018 Кузнечик CTR] + [ГОСТ 34.13-2018] Дешифруем
        Bytes plaintext = GostCipher::kuznyechikDecryptCTR(session_key, iv, ciphertext);
        std::string message(plaintext.begin(), plaintext.end());
        std::cout << "[SERVER] Сообщение от клиента: \"" << message << "\"\n";

        // ════════════════════════════════════════════════════════════════════
        // ДЕМОНСТРАЦИЯ: Магма CTR [ГОСТ 34.12-2018] + [ГОСТ 34.13-2018]
        // ════════════════════════════════════════════════════════════════════
        Bytes magma_key = GostHash::hash256(session_key); // 32-байтный ключ для Магма
        // Магма имеет 64-битный блок → IV 8 байт
        Bytes magma_iv = GostCipher::randomBytes(8);
        Bytes magma_ct = GostCipher::magmaEncryptCTR(magma_key, magma_iv, plaintext);
        Bytes magma_pt = GostCipher::magmaDecryptCTR(magma_key, magma_iv, magma_ct);
        bool magma_ok  = (magma_pt == plaintext);
        std::cout << "[SERVER] Магма CTR (ГОСТ 34.12+34.13): "
                  << (magma_ok ? "✓ (шифр/расшифр совпали)" : "✗ ОШИБКА") << "\n";

        // ════════════════════════════════════════════════════════════════════
        // ШАГ 5: Формируем ServerAck с зашифрованным ответом
        // ════════════════════════════════════════════════════════════════════
        std::string response_str = "ECHO: " + message
                                 + " | Стрибог-256 сообщения: "
                                 + Utils::toHex(GostHash::hash256(plaintext)).substr(0, 16) + "...";
        Bytes response_bytes(response_str.begin(), response_str.end());

        // [ГОСТ 34.12-2018 Кузнечик CTR] + [ГОСТ 34.13-2018] Шифруем ответ
        Bytes resp_iv     = GostCipher::randomBytes(16);
        Bytes resp_cipher = GostCipher::kuznyechikEncryptCTR(session_key, resp_iv, response_bytes);

        // [ГОСТ 34.11-2018] HMAC ответа
        Bytes resp_hmac = GostHash::hmac256(session_key, resp_cipher);

        ServerAck ack;
        ack.ok             = true;
        ack.iv_hex         = Utils::toHex(resp_iv);
        ack.ciphertext_hex = Utils::toHex(resp_cipher);
        ack.hmac_hex       = Utils::toHex(resp_hmac);

        if (!sendAll(client_fd, Proto::serialize(ack)))
            throw std::runtime_error("Ошибка отправки ServerAck");
        std::cout << "[SERVER] ServerAck отправлен (Кузнечик CTR + HMAC-Стрибог)\n";

    } catch (const std::exception& e) {
        std::cerr << "[SERVER] Ошибка обработки клиента: " << e.what() << "\n";
        // Отправляем ошибку клиенту
        ServerAck ack;
        ack.ok       = false;
        ack.error_msg= e.what();
        sendAll(client_fd, Proto::serialize(ack));
    }

    close(client_fd);
    std::cout << "[SERVER] Соединение с " << client_addr << " закрыто\n";
}

// ─── main ────────────────────────────────────────────────────────────────────
int main(int argc, char* argv[]) {
    int port = DEFAULT_PORT;
    if (argc > 1) port = std::stoi(argv[1]);

    std::cout << "╔═══════════════════════════════════════════════════╗\n";
    std::cout << "║       GOST Client-Server Demo — SERVER            ║\n";
    std::cout << "║  ГОСТ 34.10-2018 | VKO | 34.12 | 34.13 | 34.11   ║\n";
    std::cout << "╚═══════════════════════════════════════════════════╝\n\n";

    // Инициализация GOST engine
    if (!GostEngine::init()) {
        std::cerr << "[FATAL] Не удалось загрузить GOST engine.\n";
        std::cerr << "Убедитесь что установлен openssl-gost-engine и настроен openssl.cnf\n";
        return 1;
    }

    // [ГОСТ 34.10-2018] Генерация серверной ключевой пары для ЭЦП
    std::cout << "[SERVER] Генерация ключей ГОСТ 34.10-2018...\n";
    g_server_sign_kp = GostSign::generateKeyPair();
    std::cout << "[SERVER] Ключи ЭЦП сгенерированы\n";

    // [VKO ГОСТ Р 34.10-2012] Генерация серверной VKO-пары
    std::cout << "[SERVER] Генерация VKO-ключей...\n";
    g_server_vko_kp = GostVKO::generateVKOKeyPair();
    std::cout << "[SERVER] VKO-ключи сгенерированы\n";

    // Тест хэш-функций [ГОСТ 34.11-2018]
    {
        std::cout << "\n[SERVER] Самопроверка ГОСТ 34.11-2018 (Стрибог):\n";
        Bytes test_data = {'T','e','s','t',' ','G','O','S','T'};
        Bytes h256 = GostHash::hash256(test_data);
        Bytes h512 = GostHash::hash512(test_data);
        std::cout << "  Стрибог-256: " << Utils::toHex(h256) << "\n";
        std::cout << "  Стрибог-512: " << Utils::toHex(h512).substr(0,32) << "...\n";
    }

    // Создаём TCP-сокет
    int srv_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (srv_fd < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(srv_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(static_cast<uint16_t>(port));

    if (bind(srv_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        perror("bind"); close(srv_fd); return 1;
    }
    if (listen(srv_fd, 10) < 0) {
        perror("listen"); close(srv_fd); return 1;
    }

    std::cout << "\n[SERVER] Слушаю порт " << port << ". Ожидание клиентов...\n";

    while (true) {
        sockaddr_in client_addr{};
        socklen_t   client_len = sizeof(client_addr);
        int client_fd = accept(srv_fd,
                               reinterpret_cast<sockaddr*>(&client_addr),
                               &client_len);
        if (client_fd < 0) { perror("accept"); continue; }

        char addr_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, addr_str, INET_ADDRSTRLEN);
        std::string client_str = std::string(addr_str) + ":"
                               + std::to_string(ntohs(client_addr.sin_port));

        // Обрабатываем каждого клиента в отдельном потоке
        std::thread t(handleClient, client_fd, client_str);
        t.detach();
    }

    close(srv_fd);
    GostEngine::cleanup();
    return 0;
}
