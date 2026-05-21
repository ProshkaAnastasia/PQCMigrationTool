#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// Прикладной протокол защищённого обмена документами
//
// Структура пакета:
//   [4 байта: magic]  [4 байта: тип]  [4 байта: длина]
//   [8 байт: seq_no]  [данные]         [64 байта: подпись ГОСТ Р 34.10-2012]
//
// Аутентичность обеспечена ГОСТ-подписью поверх TLS-транспорта.
// ─────────────────────────────────────────────────────────────────────────────
#include <cstdint>
#include <vector>
#include <string>
#include <optional>

namespace gost { namespace network {

constexpr uint32_t PROTOCOL_MAGIC   = 0x47535444; // "GSTD"
constexpr uint32_t PROTOCOL_VERSION = 0x00010000; // 1.0.0

enum class MessageType : uint32_t {
    HELLO             = 0x0001,  // Приветствие + версия
    AUTH_REQUEST      = 0x0002,  // Запрос аутентификации
    AUTH_CHALLENGE    = 0x0003,  // Вызов (challenge) для ГОСТ-подписи
    AUTH_RESPONSE     = 0x0004,  // Ответ: подпись challenge
    AUTH_OK           = 0x0005,  // Аутентификация прошла
    AUTH_FAIL         = 0x0006,  // Ошибка аутентификации
    DOCUMENT_UPLOAD   = 0x0010,  // Загрузка документа
    DOCUMENT_SIGNED   = 0x0011,  // Подписанный документ
    DOCUMENT_REQUEST  = 0x0012,  // Запрос документа по ID
    DOCUMENT_RESPONSE = 0x0013,  // Ответ с документом
    SIGN_REQUEST      = 0x0020,  // Запрос на подписание
    SIGN_RESULT       = 0x0021,  // Результат подписания
    VERIFY_REQUEST    = 0x0022,  // Запрос на проверку подписи
    VERIFY_RESULT     = 0x0023,  // Результат проверки
    HASH_REQUEST      = 0x0030,  // Запрос хэша (Стрибог-256/512)
    HASH_RESPONSE     = 0x0031,  // Хэш документа
    ENCRYPT_REQUEST   = 0x0040,  // Запрос шифрования (Кузнечик)
    ENCRYPT_RESPONSE  = 0x0041,  // Зашифрованный документ
    ERROR             = 0xFFFF,  // Сообщение об ошибке
};

#pragma pack(push, 1)
struct MessageHeader {
    uint32_t magic;
    uint32_t type;
    uint32_t payload_len;
    uint64_t seq_no;
    uint8_t  sign[64];  // ГОСТ Р 34.10-2012 подпись (256-бит), остаток заполнен нулями
};
#pragma pack(pop)

struct Message {
    MessageType type;
    uint64_t    seq_no;
    std::vector<uint8_t> payload;
    std::vector<uint8_t> signature; // ГОСТ Р 34.10-2012
};

// Сериализация / десериализация сообщений
std::vector<uint8_t> serialize_message(const Message& msg,
                                       const std::vector<uint8_t>& sign_key_der);
std::optional<Message> deserialize_message(const std::vector<uint8_t>& data,
                                           const std::vector<uint8_t>& verify_key_der);

// Чтение/запись сообщений через файловый дескриптор
bool send_message(int fd, const Message& msg,
                  const std::vector<uint8_t>& sign_key_der);
std::optional<Message> recv_message(int fd,
                                     const std::vector<uint8_t>& verify_key_der);

// Отладочный вывод
std::string message_type_name(MessageType t);
std::string describe_message(const Message& msg);

}} // namespace gost::network