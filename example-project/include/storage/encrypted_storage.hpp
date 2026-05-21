#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// Зашифрованное хранилище документов (Кузнечик CTR + HMAC-Стрибог-256)
//
// Формат зашифрованного файла:
//   [8 байт: magic "GOSTENC\0"]
//   [32 байта: соль KDF]
//   [8 байт: CTR-nonce для Кузнечик]
//   [8 байт: размер открытого текста]
//   [N байт: зашифрованные данные]
//   [32 байта: HMAC-Стрибог-256 заголовка + данных]
// ─────────────────────────────────────────────────────────────────────────────
#include <string>
#include <vector>
#include <cstdint>
#include <functional>

namespace gost { namespace storage {

struct EncryptedHeader {
    char magic[8];          // "GOSTENC\0"
    uint8_t salt[32];       // Соль KDF (Кузнечик-CTR key derivation)
    uint8_t ctr_iv[8];      // CTR-счётчик (nonce)
    uint64_t plaintext_len; // Длина открытого текста
};

class EncryptedStorage {
public:
    // Шифрование в памяти (Кузнечик-CTR + HMAC-Стрибог-256)
    static std::vector<uint8_t> encrypt(
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& key  // 32 байта (256 бит)
    );

    // Расшифровывание из памяти (с проверкой HMAC-Стрибог-256)
    static std::vector<uint8_t> decrypt(
        const std::vector<uint8_t>& ciphertext,
        const std::vector<uint8_t>& key
    );

    // Шифрование файла
    static void encrypt_file(
        const std::string& input_path,
        const std::string& output_path,
        const std::vector<uint8_t>& key
    );

    // Расшифровывание файла
    static void decrypt_file(
        const std::string& input_path,
        const std::string& output_path,
        const std::vector<uint8_t>& key
    );

    // Потоковое шифрование с callback'ом (для больших файлов)
    static void encrypt_stream(
        std::function<size_t(uint8_t*, size_t)> reader,
        std::function<void(const uint8_t*, size_t)> writer,
        const std::vector<uint8_t>& key
    );

    // Проверка целостности (HMAC-Стрибог-256) без расшифровки
    static bool verify_integrity(
        const std::string& file_path,
        const std::vector<uint8_t>& key
    );
};

}} // namespace gost::storage