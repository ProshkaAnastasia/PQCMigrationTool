/**
 * @file client.cpp
 * @brief TCP-клиент с ГОСТ-криптографией
 *
 * ИСПОЛЬЗОВАНИЕ СТАНДАРТОВ:
 * ─────────────────────────────────────────────────────────────────────────
 * [ГОСТ 34.10-2018]
 *   • Генерация клиентской ключевой пары подписи
 *   • Верификация подписи ServerHello (аутентификация сервера)
 *   • Подпись ClientFinish (аутентификация клиента)
 *
 * [VKO ГОСТ Р 34.10-2012]
 *   • Генерация клиентской VKO-ключевой пары (paramset XA)
 *   • Выработка сессионного ключа используя UKM от сервера
 *   • deriveSharedKey(clientVKO, serverVKO, UKM)
 *
 * [ГОСТ 34.11-2018]
 *   • hash256() для формирования данных подписи ServerHello
 *   • hmac256() для защиты целостности шифртекстов
 *   • Неявно: внутри EVP_DigestSign* для ЭЦП [ГОСТ 34.10-2018]
 *
 * [ГОСТ 34.12-2018] + [ГОСТ 34.13-2018]
 *   • kuznyechikEncryptCTR() — шифрование исходящего сообщения
 *   • kuznyechikDecryptCTR() — дешифрование ответа сервера
 *   • kuznyechikEncryptCBC() + kuznyechikDecryptCBC() — демонстрация CBC
 *   • Демонстрация Стрибог-512 [ГОСТ 34.11-2018]
 * ─────────────────────────────────────────────────────────────────────────
 */

#include "gost_utils.hpp"
#include "protocol.hpp"

#include <iostream>
#include <string>
#include <sstream>
#include <stdexcept>
#include <cstring>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

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

// ─── main ────────────────────────────────────────────────────────────────────
int main(int argc, char* argv[]) {
    std::string host = "127.0.0.1";
    int port = DEFAULT_PORT;
    std::string message = "Привет, ГОСТ-сервер! ГОСТ 34.10/34.11/34.12/34.13-2018";

    if (argc > 1) host = argv[1];
    if (argc > 2) port = std::stoi(argv[2]);
    if (argc > 3) message = argv[3];

    std::cout << "╔═══════════════════════════════════════════════════╗\n";
    std::cout << "║       GOST Client-Server Demo — CLIENT            ║\n";
    std::cout << "║  ГОСТ 34.10-2018 | VKO | 34.12 | 34.13 | 34.11   ║\n";
    std::cout << "╚═══════════════════════════════════════════════════╝\n\n";

    // Инициализация GOST engine
    if (!GostEngine::init()) {
        std::cerr << "[FATAL] Не удалось загрузить GOST engine\n";
        return 1;
    }

    // ════════════════════════════════════════════════════════════════════════
    // Генерация ключей
    // ════════════════════════════════════════════════════════════════════════

    // [ГОСТ 34.10-2018] Генерация ключевой пары для ЭЦП
    std::cout << "[CLIENT] Генерация ключей ГОСТ 34.10-2018...\n";
    auto client_sign_kp = GostSign::generateKeyPair();
    std::cout << "[CLIENT] Ключи ЭЦП готовы\n";

    // [VKO ГОСТ Р 34.10-2012] Генерация ключей для выработки общего секрета
    std::cout << "[CLIENT] Генерация VKO-ключей (ГОСТ Р 34.10-2012)...\n";
    auto client_vko_kp = GostVKO::generateVKOKeyPair();
    std::cout << "[CLIENT] VKO-ключи готовы\n";

    // ════════════════════════════════════════════════════════════════════════
    // Дополнительные демонстрации алгоритмов
    // ════════════════════════════════════════════════════════════════════════
    std::cout << "\n[CLIENT] ══ Демонстрация алгоритмов ══\n";

    // [ГОСТ 34.11-2018] Стрибог-256 и Стрибог-512
    {
        Bytes test = {'G','O','S','T',' ','2','0','1','8'};
        Bytes h256 = GostHash::hash256(test);
        Bytes h512 = GostHash::hash512(test);
        std::cout << "[ГОСТ 34.11-2018] Стрибог-256: " << Utils::toHex(h256) << "\n";
        std::cout << "[ГОСТ 34.11-2018] Стрибог-512: " << Utils::toHex(h512).substr(0,32) << "...\n";
    }

    // [ГОСТ 34.12-2018] + [ГОСТ 34.13-2018] Тест Кузнечик CBC
    {
        std::cout << "\n[ГОСТ 34.12/34.13-2018] Тест Кузнечик CBC:\n";
        Bytes test_key = GostCipher::randomBytes(32);  // 256-бит ключ
        Bytes test_iv  = GostCipher::randomBytes(16);  // 128-бит IV (блок Кузнечика)
        std::string plain_str = "Тест Кузнечик CBC режим ГОСТ 34.13-2018!";
        Bytes plain_bytes(plain_str.begin(), plain_str.end());
        Bytes enc = GostCipher::kuznyechikEncryptCBC(test_key, test_iv, plain_bytes);
        Bytes dec = GostCipher::kuznyechikDecryptCBC(test_key, test_iv, enc);
        bool ok = (dec == plain_bytes);
        std::cout << "  Шифртекст (" << enc.size() << " байт): "
                  << Utils::toHex(enc).substr(0, 32) << "...\n";
        std::cout << "  Расшифровка: " << (ok ? "✓ совпадает" : "✗ ОШИБКА") << "\n";
    }

    // [ГОСТ 34.12-2018] + [ГОСТ 34.13-2018] Тест Кузнечик CTR
    {
        std::cout << "\n[ГОСТ 34.12/34.13-2018] Тест Кузнечик CTR:\n";
        Bytes test_key = GostCipher::randomBytes(32);
        Bytes test_iv  = GostCipher::randomBytes(16);
        std::string plain_str = "Тест Кузнечик CTR — поточный режим счётчика!";
        Bytes plain_bytes(plain_str.begin(), plain_str.end());
        Bytes enc = GostCipher::kuznyechikEncryptCTR(test_key, test_iv, plain_bytes);
        Bytes dec = GostCipher::kuznyechikDecryptCTR(test_key, test_iv, enc);
        bool ok = (dec == plain_bytes);
        std::cout << "  Шифртекст: " << Utils::toHex(enc).substr(0, 32) << "...\n";
        std::cout << "  Расшифровка CTR: " << (ok ? "✓ совпадает" : "✗ ОШИБКА") << "\n";
    }

    // [ГОСТ 34.11-2018] Тест HMAC-Стрибог
    {
        std::cout << "\n[ГОСТ 34.11-2018] Тест HMAC-Стрибог-256:\n";
        Bytes hmac_key  = GostCipher::randomBytes(32);
        Bytes hmac_data = {'H','M','A','C',' ','t','e','s','t'};
        Bytes hmac1 = GostHash::hmac256(hmac_key, hmac_data);
        Bytes hmac2 = GostHash::hmac256(hmac_key, hmac_data);
        bool ok = (hmac1 == hmac2);
        std::cout << "  HMAC: " << Utils::toHex(hmac1) << "\n";
        std::cout << "  Детерминизм: " << (ok ? "✓" : "✗") << "\n";
    }

    std::cout << "\n";

    // ════════════════════════════════════════════════════════════════════════
    // Сетевое соединение
    // ════════════════════════════════════════════════════════════════════════
    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) { perror("socket"); return 1; }

    sockaddr_in srv_addr{};
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port   = htons(static_cast<uint16_t>(port));
    if (inet_pton(AF_INET, host.c_str(), &srv_addr.sin_addr) <= 0) {
        std::cerr << "Неверный адрес: " << host << "\n";
        return 1;
    }

    std::cout << "[CLIENT] Подключение к " << host << ":" << port << "...\n";
    if (connect(sock_fd, reinterpret_cast<sockaddr*>(&srv_addr), sizeof(srv_addr)) < 0) {
        perror("connect");
        close(sock_fd);
        return 1;
    }
    std::cout << "[CLIENT] Подключено!\n\n";

    try {
        // ════════════════════════════════════════════════════════════════════
        // ШАГ 1: Отправить ClientHello
        // ════════════════════════════════════════════════════════════════════
        Bytes client_nonce = GostCipher::randomBytes(32);

        ClientHello ch;
        // [ГОСТ 34.10-2018] Передаём публичный ключ для верификации наших подписей
        ch.sign_pubkey_pem = GostSign::pubkeyToPem(client_sign_kp.pkey.get());
        // [VKO ГОСТ Р 34.10-2012] Передаём публичный ключ для выработки сессионного ключа
        ch.vko_pubkey_pem  = GostSign::pubkeyToPem(client_vko_kp.pkey.get());
        ch.nonce_hex       = Utils::toHex(client_nonce);

        if (!sendAll(sock_fd, Proto::serialize(ch)))
            throw std::runtime_error("Ошибка отправки ClientHello");
        std::cout << "[CLIENT] ClientHello отправлен\n";

        // ════════════════════════════════════════════════════════════════════
        // ШАГ 2: Получить ServerHello
        // ════════════════════════════════════════════════════════════════════
        std::string raw = recvAll(sock_fd);
        if (raw.empty()) throw std::runtime_error("Пустой ServerHello");
        ServerHello sh = Proto::parseServerHello(raw);
        std::cout << "[CLIENT] ServerHello получен\n";

        // Десериализуем публичные ключи сервера
        auto server_sign_pub = GostSign::pubkeyFromPem(sh.sign_pubkey_pem);
        auto server_vko_pub  = GostSign::pubkeyFromPem(sh.vko_pubkey_pem);

        // [ГОСТ 34.10-2018] Верифицируем подпись ServerHello
        std::string sign_src = sh.vko_pubkey_pem + sh.ukm_hex + ch.nonce_hex;
        Bytes sign_data(sign_src.begin(), sign_src.end());
        Bytes server_sig = Utils::fromHex(sh.signature_hex);

        bool srv_sig_ok = GostSign::verify(server_sign_pub.get(), sign_data, server_sig);
        if (!srv_sig_ok) throw std::runtime_error("Подпись сервера НЕ ВЕРНА [ГОСТ 34.10-2018]");
        std::cout << "[CLIENT] Подпись сервера верифицирована (ГОСТ 34.10-2018) ✓\n";

        // ════════════════════════════════════════════════════════════════════
        // ШАГ 3: VKO — выработка сессионного ключа
        //        [VKO ГОСТ Р 34.10-2012]
        // ════════════════════════════════════════════════════════════════════
        Bytes ukm = Utils::fromHex(sh.ukm_hex);

        // [VKO ГОСТ Р 34.10-2012] Выработка общего секрета с тем же UKM
        Bytes session_key = GostVKO::deriveSharedKey(
            client_vko_kp.pkey.get(),
            server_vko_pub.get(),
            ukm
        );

        // [ГОСТ 34.11-2018] Нормализация длины ключа через хэш
        if (session_key.size() != 32)
            session_key = GostHash::hash256(session_key);

        std::cout << "[CLIENT] Сессионный ключ выработан (VKO ГОСТ Р 34.10-2012) ✓\n";
        std::cout << "         Ключ: " << Utils::toHex(session_key).substr(0, 16) << "...\n";

        // ════════════════════════════════════════════════════════════════════
        // ШАГ 4: Формируем ClientFinish
        // ════════════════════════════════════════════════════════════════════

        // [ГОСТ 34.10-2018] Подписываем server_nonce + маркер
        std::string cli_sign_src = sh.server_nonce_hex + "CLIENT_AUTHENTICATED";
        Bytes cli_sign_data(cli_sign_src.begin(), cli_sign_src.end());
        Bytes cli_sig = GostSign::sign(client_sign_kp.pkey.get(), cli_sign_data);
        std::cout << "[CLIENT] ЭЦП ClientFinish сформирована (ГОСТ 34.10-2018) ✓\n";

        // [ГОСТ 34.12-2018 Кузнечик CTR] + [ГОСТ 34.13-2018] Шифруем сообщение
        Bytes msg_bytes(message.begin(), message.end());
        Bytes iv      = GostCipher::randomBytes(16);
        Bytes cipher  = GostCipher::kuznyechikEncryptCTR(session_key, iv, msg_bytes);

        // [ГОСТ 34.11-2018] HMAC для контроля целостности
        Bytes hmac_val = GostHash::hmac256(session_key, cipher);

        ClientFinish cf;
        cf.client_signature_hex = Utils::toHex(cli_sig);
        cf.iv_hex               = Utils::toHex(iv);
        cf.ciphertext_hex       = Utils::toHex(cipher);
        cf.hmac_hex             = Utils::toHex(hmac_val);

        if (!sendAll(sock_fd, Proto::serialize(cf)))
            throw std::runtime_error("Ошибка отправки ClientFinish");
        std::cout << "[CLIENT] ClientFinish отправлен (Кузнечик CTR + HMAC)\n";

        // ════════════════════════════════════════════════════════════════════
        // ШАГ 5: Получить ServerAck
        // ════════════════════════════════════════════════════════════════════
        raw = recvAll(sock_fd);
        if (raw.empty()) throw std::runtime_error("Пустой ServerAck");
        ServerAck ack = Proto::parseServerAck(raw);

        if (!ack.ok) throw std::runtime_error("Сервер вернул ошибку: " + ack.error_msg);

        // [ГОСТ 34.11-2018] Проверяем HMAC ответа
        Bytes resp_cipher = Utils::fromHex(ack.ciphertext_hex);
        Bytes resp_hmac_r = Utils::fromHex(ack.hmac_hex);
        Bytes resp_hmac_c = GostHash::hmac256(session_key, resp_cipher);
        if (resp_hmac_r != resp_hmac_c) throw std::runtime_error("HMAC ответа не совпадает");
        std::cout << "[CLIENT] HMAC ответа сервера проверен (ГОСТ 34.11-2018) ✓\n";

        // [ГОСТ 34.12-2018] + [ГОСТ 34.13-2018] Дешифруем ответ
        Bytes resp_iv    = Utils::fromHex(ack.iv_hex);
        Bytes resp_plain = GostCipher::kuznyechikDecryptCTR(session_key, resp_iv, resp_cipher);
        std::string response(resp_plain.begin(), resp_plain.end());
        std::cout << "\n[CLIENT] Ответ сервера: \"" << response << "\"\n";

        std::cout << "\n[CLIENT] ══ Сессия завершена успешно ══\n";

    } catch (const std::exception& e) {
        std::cerr << "\n[CLIENT] ОШИБКА: " << e.what() << "\n";
        close(sock_fd);
        GostEngine::cleanup();
        return 1;
    }

    close(sock_fd);
    GostEngine::cleanup();
    return 0;
}
