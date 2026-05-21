// ─────────────────────────────────────────────────────────────────────────────
// Производство ключей (KDF) по ГОСТ и TC26
// Стандарты: Р 50.1.113-2016, Р 1323565.1.022-2018, RFC 7836
// ─────────────────────────────────────────────────────────────────────────────
#include "crypto/kdf.hpp"
#include "crypto/hmac_streebog.hpp"
#include "crypto/grasshopper.hpp"
#include "crypto/gost_sign.hpp"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <stdexcept>
#include <cstring>

namespace gost {

// ── KDF из пароля (PBKDF2 с HMAC-Стрибог-256) ────────────────────────────────
// Аналог PBKDF2 (RFC 2898) с использованием HMAC-Стрибог-256 как PRF

std::vector<uint8_t> kdf_from_password(
    const std::string& password,
    const std::vector<uint8_t>& salt,
    uint32_t iterations,
    size_t key_len)
{
    std::vector<uint8_t> pwd_bytes(password.begin(), password.end());
    std::vector<uint8_t> out;

    uint32_t block_num = 1;
    while (out.size() < key_len) {
        // F(P, S, c, i) = U1 XOR U2 XOR ... XOR Uc
        std::vector<uint8_t> U;
        {
            // U1 = PRF(P, S || INT(i))
            std::vector<uint8_t> input = salt;
            input.push_back((block_num >> 24) & 0xFF);
            input.push_back((block_num >> 16) & 0xFF);
            input.push_back((block_num >> 8)  & 0xFF);
            input.push_back( block_num        & 0xFF);
            auto h = hmac_streebog256(pwd_bytes, input);
            U.assign(h.begin(), h.end());
        }
        std::vector<uint8_t> T = U;
        for (uint32_t i = 1; i < iterations; i++) {
            auto h = hmac_streebog256(pwd_bytes, U);
            U.assign(h.begin(), h.end());
            for (size_t j = 0; j < T.size(); j++) T[j] ^= U[j];
        }
        out.insert(out.end(), T.begin(), T.end());
        block_num++;
    }
    out.resize(key_len);
    return out;
}

// ── VKO ГОСТ Р 34.10-2012 (выработка конфиденциального ключа) ────────────────
// VKO = KDF(ECDH_shared, UKM)
// ECDH: shared_point = d_A · Q_B

std::vector<uint8_t> vko_gost_r3410_2012(
    const std::vector<uint8_t>& private_key_der,
    const std::vector<uint8_t>& public_key_der,
    const std::array<uint8_t, 8>& ukm)
{
    // Загружаем закрытый ключ (EVP_PKEY через EC)
    const unsigned char* p = private_key_der.data();
    EC_KEY* priv = d2i_ECPrivateKey(nullptr, &p, private_key_der.size());
    if (!priv) throw std::runtime_error("VKO: не удалось загрузить закрытый ключ");

    // Загружаем открытый ключ стороны B
    const EC_GROUP* group = EC_KEY_get0_group(priv);
    EC_KEY* pub_key = EC_KEY_new();
    EC_KEY_set_group(pub_key, group);
    const unsigned char* pp = public_key_der.data();
    o2i_ECPublicKey(&pub_key, &pp, public_key_der.size());

    // Вычисляем общий секрет: S = d_A · Q_B (ECDH_compute_key)
    const EC_POINT* Q_B = EC_KEY_get0_public_key(pub_key);
    BN_CTX* ctx = BN_CTX_new();
    EC_POINT* shared_point = EC_POINT_new(group);
    const BIGNUM* d_A = EC_KEY_get0_private_key(priv);
    EC_POINT_mul(group, shared_point, nullptr, Q_B, d_A, ctx);

    // Получаем координату x как общий секрет
    BIGNUM* x = BN_new();
    EC_POINT_get_affine_coordinates(group, shared_point, x, nullptr, ctx);
    std::vector<uint8_t> shared_x(32, 0);
    BN_bn2binpad(x, shared_x.data(), 32);

    // KDF: VKO = HMAC-Stribog256(shared_x, UKM)
    std::vector<uint8_t> ukm_vec(ukm.begin(), ukm.end());
    auto result_arr = hmac_streebog256(shared_x, ukm_vec);
    std::vector<uint8_t> result(result_arr.begin(), result_arr.end());

    // Освобождение ресурсов
    BN_free(x);
    EC_POINT_free(shared_point);
    BN_CTX_free(ctx);
    EC_KEY_free(priv);
    EC_KEY_free(pub_key);
    return result;
}

// ── KDF-дерево (Р 50.1.113-2016) ─────────────────────────────────────────────

std::vector<uint8_t> kdf_tree_gostr3411_2012_256(
    const std::vector<uint8_t>& k_root,
    const std::string& label,
    const std::vector<uint8_t>& seed,
    size_t r)
{
    // KDF_TREE_GOSTR3411_2012_256(K_root, label, seed, r)
    // = HMAC-Stribog256(K_root, R || label || 0x00 || seed || L)
    std::vector<uint8_t> input;
    // R — счётчик (4 байта big-endian)
    input.push_back((r >> 24) & 0xFF);
    input.push_back((r >> 16) & 0xFF);
    input.push_back((r >>  8) & 0xFF);
    input.push_back( r        & 0xFF);
    input.insert(input.end(), label.begin(), label.end());
    input.push_back(0x00);
    input.insert(input.end(), seed.begin(), seed.end());
    // L = 256 бит = 0x00000100
    input.push_back(0x00); input.push_back(0x00);
    input.push_back(0x01); input.push_back(0x00);
    auto h = hmac_streebog256(k_root, input);
    return std::vector<uint8_t>(h.begin(), h.end());
}

// ── ACPKM (Р 1323565.1.017-2018) ─────────────────────────────────────────────

AcpkmKeySchedule::AcpkmKeySchedule(const std::vector<uint8_t>& initial_key,
                                   size_t section_size)
    : current_key_(initial_key), section_size_(section_size), current_section_(0) {}

std::vector<uint8_t> AcpkmKeySchedule::derive_next_key(const std::vector<uint8_t>& key) {
    // ACPKM: производим следующий ключ шифрованием специальной константы C*
    // C* = 0x6d293cd6...2f3a4 (фиксированная 256-битная константа из стандарта)
    static const uint8_t ACPKM_CONST[32] = {
        0x6d, 0x29, 0x3c, 0xd6, 0xb4, 0x5c, 0x84, 0x4f,
        0x22, 0x84, 0xab, 0x91, 0xe7, 0x4e, 0xaf, 0x32,
        0x16, 0x3b, 0xa9, 0x60, 0xa3, 0xf4, 0xb0, 0xe8,
        0x4e, 0xaa, 0x50, 0xfc, 0x9e, 0x5a, 0x4c, 0x88,
    };
    // Новый ключ = шифрование константы текущим ключом
    if (key.size() != 32) throw std::runtime_error("ACPKM: неверная длина ключа");
    GKey k;
    std::memcpy(k.data(), key.data(), 32);
    Grasshopper cipher(k);
    // Шифруем два блока (32 байта) константы
    GBlock b0, b1;
    std::memcpy(b0.data(), ACPKM_CONST,      16);
    std::memcpy(b1.data(), ACPKM_CONST + 16, 16);
    GBlock enc0 = cipher.encrypt_block(b0);
    GBlock enc1 = cipher.encrypt_block(b1);
    std::vector<uint8_t> new_key(32);
    std::memcpy(new_key.data(),      enc0.data(), 16);
    std::memcpy(new_key.data() + 16, enc1.data(), 16);
    return new_key;
}

std::vector<uint8_t> AcpkmKeySchedule::get_key_for_position(uint64_t byte_pos) {
    uint64_t section = byte_pos / section_size_;
    while (current_section_ < section) {
        current_key_ = derive_next_key(current_key_);
        current_section_++;
    }
    return current_key_;
}

// ── Обёртка ключей (Key Wrap) на Кузнечик ────────────────────────────────────
// Аналог RFC 3394 (AES Key Wrap Algorithm), но с Кузнечиком

std::vector<uint8_t> key_wrap_grasshopper(
    const std::vector<uint8_t>& key_to_wrap,
    const std::vector<uint8_t>& wrapping_key)
{
    if (wrapping_key.size() != 32) throw std::invalid_argument("key_wrap: wrapping_key должен быть 32 байта");

    GKey wk;
    std::memcpy(wk.data(), wrapping_key.data(), 32);
    Grasshopper cipher(wk);

    // Дополнение до кратного 16 байтам
    size_t padded = ((key_to_wrap.size() + 15) / 16) * 16;
    std::vector<uint8_t> data(padded + 8, 0);
    // ICV (integrity check value): первые 8 байт = Стрибог-256 хэш ключа
    // (упрощённо: нули для примера)
    std::memcpy(data.data() + 8, key_to_wrap.data(), key_to_wrap.size());

    // Wrap: 6 итераций (RFC 3394 style)
    size_t n = padded / 8;
    uint64_t A = 0xA6A6A6A6A6A6A6A6ULL;  // IV
    std::vector<uint64_t> R(n + 1, 0);
    for (size_t i = 1; i <= n; i++) {
        uint8_t tmp[8];
        std::memcpy(tmp, data.data() + 8*i, 8);
        uint64_t val;
        std::memcpy(&val, tmp, 8);
        R[i] = val;
    }
    for (int j = 0; j < 6; j++) {
        for (size_t i = 1; i <= n; i++) {
            GBlock B = {};
            std::memcpy(B.data(),     &A,    8);
            std::memcpy(B.data() + 8, &R[i], 8);
            GBlock enc = cipher.encrypt_block(B);
            uint64_t t = (uint64_t)(j * n + i);
            uint64_t a_new;
            std::memcpy(&a_new, enc.data(), 8);
            A = a_new ^ __builtin_bswap64(t);
            std::memcpy(&R[i], enc.data() + 8, 8);
        }
    }
    std::vector<uint8_t> out(8 + 8*n);
    std::memcpy(out.data(), &A, 8);
    for (size_t i = 1; i <= n; i++) std::memcpy(out.data() + 8*i, &R[i], 8);
    return out;
}

std::vector<uint8_t> key_unwrap_grasshopper(
    const std::vector<uint8_t>& wrapped_key,
    const std::vector<uint8_t>& wrapping_key)
{
    if (wrapping_key.size() != 32) throw std::invalid_argument("key_unwrap: wrapping_key должен быть 32 байта");
    GKey wk;
    std::memcpy(wk.data(), wrapping_key.data(), 32);
    Grasshopper cipher(wk);

    size_t n = (wrapped_key.size() - 8) / 8;
    uint64_t A;
    std::memcpy(&A, wrapped_key.data(), 8);
    std::vector<uint64_t> R(n + 1);
    for (size_t i = 1; i <= n; i++) {
        std::memcpy(&R[i], wrapped_key.data() + 8*i, 8);
    }
    for (int j = 5; j >= 0; j--) {
        for (size_t i = n; i >= 1; i--) {
            uint64_t t = (uint64_t)(j * n + i);
            uint64_t a_xored = A ^ __builtin_bswap64(t);
            GBlock B = {};
            std::memcpy(B.data(),     &a_xored, 8);
            std::memcpy(B.data() + 8, &R[i],    8);
            GBlock dec = cipher.decrypt_block(B);
            std::memcpy(&A,    dec.data(),     8);
            std::memcpy(&R[i], dec.data() + 8, 8);
        }
    }
    std::vector<uint8_t> out(8 * n);
    for (size_t i = 1; i <= n; i++) std::memcpy(out.data() + 8*(i-1), &R[i], 8);
    return out;
}

} // namespace gost