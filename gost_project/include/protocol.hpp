/**
 * @file protocol.hpp
 * @brief Структуры сетевого протокола клиент-сервер
 *
 * Протокол рукопожатия:
 *  1. CLIENT → SERVER: ClientHello  { client_pubkey_pem, vko_pubkey_pem }
 *  2. SERVER → CLIENT: ServerHello  { server_pubkey_pem, vko_pubkey_pem, ukm, server_signature }
 *  3. CLIENT → SERVER: ClientFinish { client_signature, encrypted_message }
 *  4. SERVER → CLIENT: ServerAck    { status, hmac, encrypted_response }
 *
 * Криптография протокола:
 *  - Аутентификация:        ГОСТ 34.10-2018 (ЭЦП)
 *  - Хэш для ЭЦП:           ГОСТ 34.11-2018 (Стрибог-256)
 *  - Выработка сессионного ключа: VKO ГОСТ Р 34.10-2012
 *  - Шифрование сессии:    ГОСТ 34.12-2018 Кузнечик CTR (ГОСТ 34.13-2018)
 *  - Целостность (HMAC):    ГОСТ 34.11-2018 Стрибог-256
 */

#pragma once
#include <string>
#include <vector>
#include <cstdint>

// Размер сетевого буфера
constexpr size_t NET_BUFFER_SIZE = 65536;

// Порт по умолчанию
constexpr int DEFAULT_PORT = 7777;

/**
 * Тип сообщения протокола
 */
enum class MsgType : uint8_t {
    CLIENT_HELLO  = 0x01,
    SERVER_HELLO  = 0x02,
    CLIENT_FINISH = 0x03,
    SERVER_ACK    = 0x04,
    ERROR_MSG     = 0xFF
};

/**
 * Заголовок сетевого сообщения
 */
#pragma pack(push, 1)
struct MsgHeader {
    uint8_t  type;      // MsgType
    uint32_t length;    // длина тела в байтах (big-endian)
};
#pragma pack(pop)

/**
 * Шаг 1: Клиент → Сервер
 * Содержит публичные ключи клиента
 */
struct ClientHello {
    std::string sign_pubkey_pem;  // ГОСТ 34.10-2018: ключ для верификации подписей
    std::string vko_pubkey_pem;   // VKO ГОСТ Р 34.10-2012: ключ для выработки сессионного ключа
    std::string nonce_hex;        // случайный nonce клиента (32 байта, hex)
};

/**
 * Шаг 2: Сервер → Клиент
 * Содержит публичные ключи сервера + подпись серверных данных
 */
struct ServerHello {
    std::string sign_pubkey_pem;  // ГОСТ 34.10-2018: ключ сервера для подписи
    std::string vko_pubkey_pem;   // VKO ГОСТ Р 34.10-2012: ключ сервера для выработки ключа
    std::string ukm_hex;          // UKM для VKO (8 байт, hex) — [VKO ГОСТ Р 34.10-2012]
    std::string server_nonce_hex; // nonce сервера
    std::string signature_hex;    // ГОСТ 34.10-2018 подпись (sign_pubkey + vko_pubkey + ukm + client_nonce)
};

/**
 * Шаг 3: Клиент → Сервер
 * Подпись + зашифрованное сообщение
 */
struct ClientFinish {
    std::string client_signature_hex; // ГОСТ 34.10-2018 подпись (server_nonce + "OK")
    std::string iv_hex;               // IV для шифрования (16 байт, hex) — ГОСТ 34.13-2018
    std::string ciphertext_hex;       // ГОСТ 34.12-2018 Кузнечик CTR — зашифрованное сообщение
    std::string hmac_hex;             // HMAC-Стрибог-256 по ciphertext — ГОСТ 34.11-2018
};

/**
 * Шаг 4: Сервер → Клиент
 * Подтверждение + зашифрованный ответ
 */
struct ServerAck {
    bool        ok;
    std::string iv_hex;           // IV для ответа — ГОСТ 34.13-2018
    std::string ciphertext_hex;   // ГОСТ 34.12-2018 Кузнечик CTR
    std::string hmac_hex;         // HMAC-Стрибог-256 — ГОСТ 34.11-2018
    std::string error_msg;        // только если !ok
};

// ─── Сериализация (простой текстовый формат key=value\n) ─────────────────────
namespace Proto {
    std::string serialize(const ClientHello&  m);
    std::string serialize(const ServerHello&  m);
    std::string serialize(const ClientFinish& m);
    std::string serialize(const ServerAck&    m);

    ClientHello  parseClientHello(const std::string& s);
    ServerHello  parseServerHello(const std::string& s);
    ClientFinish parseClientFinish(const std::string& s);
    ServerAck    parseServerAck(const std::string& s);

    // Вспомогательные функции
    std::string  getField(const std::string& s, const std::string& key);
    std::string  encodeMultiline(const std::string& pem); // заменяет \n → \\n
    std::string  decodeMultiline(const std::string& s);   // обратно
}
