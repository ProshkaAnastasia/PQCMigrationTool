// ─────────────────────────────────────────────────────────────────────────────
// Зашифрованное хранилище (Кузнечик-CTR + HMAC-Стрибог-256)
//
// Формат файла:
//   [8 байт]  magic = "GOSTENC\0"
//   [32 байта] соль KDF
//   [8 байт]  CTR-nonce
//   [8 байт]  размер открытого текста (uint64_t LE)
//   [N байт]  зашифрованный текст (Кузнечик-CTR)
//   [32 байта] HMAC-Стрибог-256(magic+salt+nonce+len+ciphertext)
//
// KDF: HKDF-Стрибог-256 от (key, salt) → enc_key (32 байт) + mac_key (32 байта)
// ─────────────────────────────────────────────────────────────────────────────
#include "storage/encrypted_storage.hpp"
#include "crypto/grasshopper.hpp"
#include "crypto/hmac_streebog.hpp"
#include "common/utils.hpp"
#include <fstream>
#include <stdexcept>
#include <cstring>

namespace gost { namespace storage {

static constexpr char MAGIC[8] = {'G','O','S','T','E','N','C','\0'};
static constexpr size_t HMAC_SIZE = 32;
static constexpr size_t HEADER_BARE = sizeof(EncryptedHeader);

// Выводим два ключа через HKDF-Стрибог-256
static void derive_keys(const std::vector<uint8_t>& master_key,
                         const uint8_t* salt, size_t salt_len,
                         std::vector<uint8_t>& enc_key,
                         std::vector<uint8_t>& mac_key) {
    std::vector<uint8_t> salt_vec(salt, salt + salt_len);
    std::vector<uint8_t> info_enc = {'e','n','c'};
    std::vector<uint8_t> info_mac = {'m','a','c'};
    enc_key = hkdf_streebog256(master_key, salt_vec, info_enc, 32);
    mac_key = hkdf_streebog256(master_key, salt_vec, info_mac, 32);
}

// Преобразуем Digest256 (array<uint8_t,32>) в vector для сравнения
static std::vector<uint8_t> digest_to_vec(const Digest256& d) {
    return std::vector<uint8_t>(d.begin(), d.end());
}

std::vector<uint8_t> EncryptedStorage::encrypt(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key)
{
    if (key.size() != 32)
        throw std::invalid_argument("EncryptedStorage: ключ должен быть 32 байта");

    auto salt = utils::secure_random(32);
    auto nonce_vec = utils::secure_random(8);

    std::vector<uint8_t> enc_key, mac_key;
    derive_keys(key, salt.data(), salt.size(), enc_key, mac_key);

    // Кузнечик-CTR: IV = 8-байтный nonce
    Grasshopper gh(enc_key.data(), enc_key.size());
    std::array<uint8_t, 8> ctr_iv;
    std::copy(nonce_vec.begin(), nonce_vec.end(), ctr_iv.begin());
    auto ciphertext = gh.encrypt_ctr(plaintext, ctr_iv);

    // Собираем заголовок
    EncryptedHeader hdr = {};
    std::memcpy(hdr.magic, MAGIC, 8);
    std::copy(salt.begin(), salt.end(), hdr.salt);
    std::copy(nonce_vec.begin(), nonce_vec.end(), hdr.ctr_iv);
    hdr.plaintext_len = (uint64_t)plaintext.size();

    // HMAC-Стрибог-256(header || ciphertext)
    std::vector<uint8_t> mac_input(HEADER_BARE + ciphertext.size());
    std::memcpy(mac_input.data(), &hdr, HEADER_BARE);
    std::memcpy(mac_input.data() + HEADER_BARE, ciphertext.data(), ciphertext.size());
    auto mac = hmac_streebog256(mac_key, mac_input);  // returns Digest256

    // Собираем blob
    std::vector<uint8_t> out(HEADER_BARE + ciphertext.size() + HMAC_SIZE);
    std::memcpy(out.data(), &hdr, HEADER_BARE);
    std::memcpy(out.data() + HEADER_BARE, ciphertext.data(), ciphertext.size());
    std::memcpy(out.data() + HEADER_BARE + ciphertext.size(), mac.data(), HMAC_SIZE);
    return out;
}

std::vector<uint8_t> EncryptedStorage::decrypt(
    const std::vector<uint8_t>& blob,
    const std::vector<uint8_t>& key)
{
    if (key.size() != 32)
        throw std::invalid_argument("EncryptedStorage: ключ должен быть 32 байта");
    if (blob.size() < HEADER_BARE + HMAC_SIZE)
        throw std::runtime_error("EncryptedStorage: слишком короткий blob");

    EncryptedHeader hdr;
    std::memcpy(&hdr, blob.data(), HEADER_BARE);

    if (std::memcmp(hdr.magic, MAGIC, 8) != 0)
        throw std::runtime_error("EncryptedStorage: неверная магическая последовательность");

    size_t ct_size = blob.size() - HEADER_BARE - HMAC_SIZE;

    std::vector<uint8_t> enc_key, mac_key;
    derive_keys(key, hdr.salt, 32, enc_key, mac_key);

    // Проверяем HMAC-Стрибог-256
    std::vector<uint8_t> mac_input(HEADER_BARE + ct_size);
    std::memcpy(mac_input.data(), blob.data(), HEADER_BARE + ct_size);
    auto expected_mac = hmac_streebog256(mac_key, mac_input);  // Digest256

    const uint8_t* actual_mac_ptr = blob.data() + HEADER_BARE + ct_size;
    // Константное время сравнение вручную (Digest256 vs raw bytes)
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < HMAC_SIZE; ++i)
        diff |= expected_mac[i] ^ actual_mac_ptr[i];
    if (diff != 0)
        throw std::runtime_error("EncryptedStorage: HMAC не совпал — данные повреждены");

    // Расшифровываем Кузнечик-CTR
    std::vector<uint8_t> ciphertext(blob.data() + HEADER_BARE,
                                    blob.data() + HEADER_BARE + ct_size);
    Grasshopper gh(enc_key.data(), enc_key.size());
    std::array<uint8_t, 8> ctr_iv;
    std::copy(hdr.ctr_iv, hdr.ctr_iv + 8, ctr_iv.begin());
    auto plaintext = gh.decrypt_ctr(ciphertext, ctr_iv);
    plaintext.resize(hdr.plaintext_len);
    return plaintext;
}

void EncryptedStorage::encrypt_file(const std::string& in,
                                    const std::string& out,
                                    const std::vector<uint8_t>& key) {
    auto plaintext = utils::read_file(in);
    auto blob = encrypt(plaintext, key);
    utils::write_file(out, blob);
}

void EncryptedStorage::decrypt_file(const std::string& in,
                                    const std::string& out,
                                    const std::vector<uint8_t>& key) {
    auto blob = utils::read_file(in);
    auto plaintext = decrypt(blob, key);
    utils::write_file(out, plaintext);
}

void EncryptedStorage::encrypt_stream(
    std::function<size_t(uint8_t*, size_t)> reader,
    std::function<void(const uint8_t*, size_t)> writer,
    const std::vector<uint8_t>& key)
{
    std::vector<uint8_t> buf(65536);
    std::vector<uint8_t> all;
    size_t n;
    while ((n = reader(buf.data(), buf.size())) > 0)
        all.insert(all.end(), buf.begin(), buf.begin() + n);
    auto blob = encrypt(all, key);
    writer(blob.data(), blob.size());
}

bool EncryptedStorage::verify_integrity(const std::string& file_path,
                                         const std::vector<uint8_t>& key) {
    try {
        auto blob = utils::read_file(file_path);
        decrypt(blob, key);
        return true;
    } catch (...) {
        return false;
    }
}

}} // namespace gost::storage