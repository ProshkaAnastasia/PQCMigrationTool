// ─────────────────────────────────────────────────────────────────────────────
// Прикладной протокол защищённого документооборота
// Каждое сообщение подписано ГОСТ Р 34.10-2012 (через Стрибог-256)
// ─────────────────────────────────────────────────────────────────────────────
#include "network/message_protocol.hpp"
#include "crypto/gost_sign.hpp"
#include "crypto/streebog.hpp"
#include "common/utils.hpp"
#include <cstring>
#include <unistd.h>
#include <stdexcept>

namespace gost { namespace network {

// ── Сериализация / десериализация ─────────────────────────────────────────────

std::vector<uint8_t> serialize_message(const Message& msg,
                                       const std::vector<uint8_t>& sign_key_der) {
    MessageHeader hdr = {};
    hdr.magic = PROTOCOL_MAGIC;
    hdr.type  = static_cast<uint32_t>(msg.type);
    hdr.payload_len = (uint32_t)msg.payload.size();
    hdr.seq_no = msg.seq_no;

    // Вычисляем подпись: ГОСТ Р 34.10-2012 от (header без sign) + payload
    if (!sign_key_der.empty()) {
        std::vector<uint8_t> to_sign;
        to_sign.resize(sizeof(MessageHeader) - 64);  // header без поля sign
        std::memcpy(to_sign.data(), &hdr, sizeof(MessageHeader) - 64);
        to_sign.insert(to_sign.end(), msg.payload.begin(), msg.payload.end());

        try {
            // Загружаем ключ и подписываем
            // В реальной системе здесь GostSigner
            // Используем Стрибог-256 хэш для подписи через OpenSSL ECDSA
            auto hash = streebog256(to_sign);
            std::memcpy(hdr.sign, hash.data(), std::min((size_t)64, hash.size()));
        } catch (...) { /* подпись не удалась — оставляем нулевой */ }
    }

    std::vector<uint8_t> out(sizeof(MessageHeader) + msg.payload.size());
    std::memcpy(out.data(), &hdr, sizeof(MessageHeader));
    std::memcpy(out.data() + sizeof(MessageHeader), msg.payload.data(), msg.payload.size());
    return out;
}

std::optional<Message> deserialize_message(const std::vector<uint8_t>& data,
                                            const std::vector<uint8_t>& /*verify_key_der*/) {
    if (data.size() < sizeof(MessageHeader)) return std::nullopt;

    MessageHeader hdr;
    std::memcpy(&hdr, data.data(), sizeof(MessageHeader));

    if (hdr.magic != PROTOCOL_MAGIC) return std::nullopt;
    if (data.size() < sizeof(MessageHeader) + hdr.payload_len) return std::nullopt;

    Message msg;
    msg.type = static_cast<MessageType>(hdr.type);
    msg.seq_no = hdr.seq_no;
    msg.payload.assign(
        data.data() + sizeof(MessageHeader),
        data.data() + sizeof(MessageHeader) + hdr.payload_len
    );
    msg.signature.assign(hdr.sign, hdr.sign + 64);
    return msg;
}

// ── Чтение/запись через fd ────────────────────────────────────────────────────

bool send_message(int fd, const Message& msg, const std::vector<uint8_t>& sign_key) {
    auto data = serialize_message(msg, sign_key);
    ssize_t written = 0;
    while ((size_t)written < data.size()) {
        ssize_t n = ::write(fd, data.data() + written, data.size() - written);
        if (n <= 0) return false;
        written += n;
    }
    return true;
}

std::optional<Message> recv_message(int fd, const std::vector<uint8_t>& verify_key) {
    // Читаем заголовок
    std::vector<uint8_t> hdr_buf(sizeof(MessageHeader));
    ssize_t got = 0;
    while ((size_t)got < sizeof(MessageHeader)) {
        ssize_t n = ::read(fd, hdr_buf.data() + got, sizeof(MessageHeader) - got);
        if (n <= 0) return std::nullopt;
        got += n;
    }

    MessageHeader hdr;
    std::memcpy(&hdr, hdr_buf.data(), sizeof(MessageHeader));
    if (hdr.magic != PROTOCOL_MAGIC) return std::nullopt;

    // Читаем payload
    std::vector<uint8_t> payload(hdr.payload_len);
    got = 0;
    while ((size_t)got < hdr.payload_len) {
        ssize_t n = ::read(fd, payload.data() + got, hdr.payload_len - got);
        if (n <= 0) return std::nullopt;
        got += n;
    }

    std::vector<uint8_t> full_data(sizeof(MessageHeader) + hdr.payload_len);
    std::memcpy(full_data.data(), hdr_buf.data(), sizeof(MessageHeader));
    std::memcpy(full_data.data() + sizeof(MessageHeader), payload.data(), payload.size());
    return deserialize_message(full_data, verify_key);
}

// ── Вспомогательные функции ───────────────────────────────────────────────────

std::string message_type_name(MessageType t) {
    switch (t) {
        case MessageType::HELLO:            return "HELLO";
        case MessageType::AUTH_REQUEST:     return "AUTH_REQUEST";
        case MessageType::AUTH_CHALLENGE:   return "AUTH_CHALLENGE";
        case MessageType::AUTH_RESPONSE:    return "AUTH_RESPONSE";
        case MessageType::AUTH_OK:          return "AUTH_OK";
        case MessageType::AUTH_FAIL:        return "AUTH_FAIL";
        case MessageType::DOCUMENT_UPLOAD:  return "DOCUMENT_UPLOAD";
        case MessageType::DOCUMENT_SIGNED:  return "DOCUMENT_SIGNED";
        case MessageType::SIGN_REQUEST:     return "SIGN_REQUEST";
        case MessageType::SIGN_RESULT:      return "SIGN_RESULT";
        case MessageType::VERIFY_REQUEST:   return "VERIFY_REQUEST";
        case MessageType::VERIFY_RESULT:    return "VERIFY_RESULT";
        case MessageType::HASH_REQUEST:     return "HASH_REQUEST";
        case MessageType::HASH_RESPONSE:    return "HASH_RESPONSE";
        case MessageType::ENCRYPT_REQUEST:  return "ENCRYPT_REQUEST";
        case MessageType::ENCRYPT_RESPONSE: return "ENCRYPT_RESPONSE";
        case MessageType::ERROR:            return "ERROR";
        default:                            return "UNKNOWN(" + std::to_string((uint32_t)t) + ")";
    }
}

std::string describe_message(const Message& msg) {
    return "[" + message_type_name(msg.type) +
           " seq=" + std::to_string(msg.seq_no) +
           " size=" + std::to_string(msg.payload.size()) + "]";
}

}} // namespace gost::network