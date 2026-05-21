// ─────────────────────────────────────────────────────────────────────────────
// Тесты ГОСТ Р 34.12-2015 Кузнечик (Grasshopper)
// ─────────────────────────────────────────────────────────────────────────────
#include "test_helper.hpp"
#include "crypto/grasshopper.hpp"
#include "common/utils.hpp"

using namespace gost;

// Вспомогательная функция: вектор → GBlock
static GBlock to_gblock(const std::vector<uint8_t>& v) {
    GBlock b{};
    if (v.size() == 16) std::copy(v.begin(), v.end(), b.begin());
    return b;
}
static std::array<uint8_t, 8> to_iv8(const std::vector<uint8_t>& v) {
    std::array<uint8_t, 8> a{};
    if (v.size() >= 8) std::copy(v.begin(), v.begin() + 8, a.begin());
    return a;
}

void register_grasshopper_tests() {

    add_test("Grasshopper_init_32byte_key", []() -> bool {
        auto key = utils::secure_random(32);
        Grasshopper gh(key.data(), key.size());
        (void)gh;
        return true;
    });

    add_test("Grasshopper_encrypt_decrypt_block", []() -> bool {
        auto key = utils::secure_random(32);
        Grasshopper gh(key.data(), key.size());

        GBlock plain{};
        for (int i = 0; i < 16; ++i) plain[i] = (uint8_t)i;

        auto cipher = gh.encrypt_block(plain);
        ASSERT_TRUE(cipher != plain);

        auto decrypted = gh.decrypt_block(cipher);
        ASSERT_TRUE(decrypted == plain);
        return true;
    });

    add_test("Grasshopper_different_keys_different_output", []() -> bool {
        auto key1 = utils::secure_random(32);
        auto key2 = utils::secure_random(32);
        ASSERT_NE(key1, key2);

        GBlock plain{};
        plain.fill(0xAB);
        auto c1 = Grasshopper(key1.data(), key1.size()).encrypt_block(plain);
        auto c2 = Grasshopper(key2.data(), key2.size()).encrypt_block(plain);
        ASSERT_TRUE(c1 != c2);
        return true;
    });

    add_test("Grasshopper_ctr_roundtrip", []() -> bool {
        auto key = utils::secure_random(32);
        Grasshopper gh(key.data(), key.size());

        std::vector<uint8_t> plain(100, 0x42);
        auto iv = to_iv8(utils::secure_random(8));

        auto cipher = gh.encrypt_ctr(plain, iv);
        ASSERT_TRUE(cipher.size() == 100);
        ASSERT_NE(cipher, plain);

        auto recovered = gh.decrypt_ctr(cipher, iv);
        ASSERT_TRUE(recovered == plain);
        return true;
    });

    add_test("Grasshopper_ctr_is_symmetric", []() -> bool {
        // CTR: шифрование и расшифрование — одна операция
        auto key = utils::secure_random(32);
        Grasshopper gh(key.data(), key.size());
        auto iv = to_iv8(utils::secure_random(8));

        std::vector<uint8_t> plain(64, 0xCC);
        auto enc = gh.encrypt_ctr(plain, iv);
        auto dec = gh.encrypt_ctr(enc, iv);  // Применяем повторно
        ASSERT_TRUE(dec == plain);
        return true;
    });

    add_test("Grasshopper_ctr_different_ivs", []() -> bool {
        auto key = utils::secure_random(32);
        Grasshopper gh(key.data(), key.size());

        std::vector<uint8_t> plain(32, 0x55);
        auto iv1 = to_iv8(utils::secure_random(8));
        auto iv2 = to_iv8(utils::secure_random(8));

        auto c1 = gh.encrypt_ctr(plain, iv1);
        auto c2 = gh.encrypt_ctr(plain, iv2);
        ASSERT_NE(c1, c2);
        return true;
    });

    add_test("Grasshopper_block_constants", []() -> bool {
        ASSERT_TRUE(GRASSHOPPER_BLOCK_SIZE == 16);
        ASSERT_TRUE(GRASSHOPPER_KEY_SIZE == 32);
        ASSERT_TRUE(GRASSHOPPER_ROUNDS == 10);
        return true;
    });

    add_test("Grasshopper_mac_deterministic", []() -> bool {
        auto key = utils::secure_random(32);
        Grasshopper gh(key.data(), key.size());

        std::vector<uint8_t> data(64, 0xAA);
        auto mac1 = gh.mac(data);
        auto mac2 = gh.mac(data);
        ASSERT_TRUE(mac1.size() == 8);
        ASSERT_TRUE(mac1 == mac2);
        return true;
    });

    add_test("Grasshopper_mac_sensitive", []() -> bool {
        auto key = utils::secure_random(32);
        Grasshopper gh(key.data(), key.size());

        std::vector<uint8_t> data(64, 0xAA);
        auto mac1 = gh.mac(data);
        data[0] ^= 0xFF;
        auto mac2 = gh.mac(data);
        ASSERT_TRUE(mac1 != mac2);
        return true;
    });

    add_test("Grasshopper_ctr_large_data", []() -> bool {
        auto key = utils::secure_random(32);
        Grasshopper gh(key.data(), key.size());

        std::vector<uint8_t> plain(1024, 0);
        for (size_t i = 0; i < plain.size(); ++i) plain[i] = (uint8_t)(i & 0xFF);
        auto iv = to_iv8(utils::secure_random(8));

        auto cipher = gh.encrypt_ctr(plain, iv);
        auto dec = gh.decrypt_ctr(cipher, iv);
        ASSERT_TRUE(dec == plain);
        return true;
    });
}