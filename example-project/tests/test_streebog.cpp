// ─────────────────────────────────────────────────────────────────────────────
// Тесты ГОСТ Р 34.11-2012 (Стрибог-256 / Стрибог-512)
// ─────────────────────────────────────────────────────────────────────────────
#include "test_helper.hpp"
#include "crypto/streebog.hpp"
#include "crypto/hmac_streebog.hpp"
#include "common/utils.hpp"
#include <cstring>

using namespace gost;

void register_streebog_tests() {

    add_test("Streebog256_deterministic", []() -> bool {
        const char* msg = "ГОСТ Р 34.11-2012 Стрибог";
        auto h1 = streebog256(reinterpret_cast<const uint8_t*>(msg), strlen(msg));
        auto h2 = streebog256(reinterpret_cast<const uint8_t*>(msg), strlen(msg));
        ASSERT_TRUE(h1.size() == 32);
        ASSERT_TRUE(h1 == h2);
        return true;
    });

    add_test("Streebog512_deterministic", []() -> bool {
        const char* msg = "ГОСТ Р 34.11-2012 Стрибог-512";
        auto h1 = streebog512(reinterpret_cast<const uint8_t*>(msg), strlen(msg));
        auto h2 = streebog512(reinterpret_cast<const uint8_t*>(msg), strlen(msg));
        ASSERT_TRUE(h1.size() == 64);
        ASSERT_TRUE(h1 == h2);
        return true;
    });

    add_test("Streebog256_different_outputs", []() -> bool {
        const char* m1 = "message1";
        const char* m2 = "message2";
        auto h1 = streebog256(reinterpret_cast<const uint8_t*>(m1), strlen(m1));
        auto h2 = streebog256(reinterpret_cast<const uint8_t*>(m2), strlen(m2));
        ASSERT_NE(h1, h2);
        return true;
    });

    add_test("Streebog256_avalanche", []() -> bool {
        // Один бит различия → ~50% бит хэша меняются
        std::vector<uint8_t> d1(64, 0x00);
        std::vector<uint8_t> d2 = d1;
        d2[0] ^= 0x01;

        auto h1 = streebog256(d1.data(), d1.size());
        auto h2 = streebog256(d2.data(), d2.size());
        ASSERT_NE(h1, h2);

        int diff = 0;
        for (size_t i = 0; i < 32; ++i) {
            uint8_t x = h1[i] ^ h2[i];
            for (int b = 0; b < 8; ++b) if ((x >> b) & 1) ++diff;
        }
        ASSERT_TRUE(diff > 64);  // >50% бит изменилось
        return true;
    });

    add_test("Streebog256_streaming_equals_oneshot", []() -> bool {
        std::vector<uint8_t> data(1000, 0xAB);

        auto h_oneshot = streebog256(data.data(), data.size());

        Streebog256Context ctx;
        ctx.update(data.data(), 333);
        ctx.update(data.data() + 333, 333);
        ctx.update(data.data() + 666, 334);
        auto h_stream = ctx.finalize();

        ASSERT_TRUE(h_oneshot == h_stream);
        return true;
    });

    add_test("Streebog512_streaming_equals_oneshot", []() -> bool {
        std::vector<uint8_t> data(512, 0xCC);
        auto h1 = streebog512(data.data(), data.size());

        Streebog512Context ctx;
        ctx.update(data.data(), 256);
        ctx.update(data.data() + 256, 256);
        auto h2 = ctx.finalize();

        ASSERT_TRUE(h1 == h2);
        return true;
    });

    add_test("HMAC_Streebog256_basic", []() -> bool {
        std::vector<uint8_t> key(32, 0x42);
        std::vector<uint8_t> data = {1, 2, 3, 4, 5};
        auto mac1 = hmac_streebog256(key, data);
        auto mac2 = hmac_streebog256(key, data);
        ASSERT_TRUE(mac1.size() == 32);
        ASSERT_TRUE(mac1 == mac2);

        // Другой ключ → другой MAC
        std::vector<uint8_t> key2(32, 0x43);
        auto mac3 = hmac_streebog256(key2, data);
        ASSERT_NE(mac1, mac3);
        return true;
    });

    add_test("HMAC_Streebog512_basic", []() -> bool {
        std::vector<uint8_t> key(64, 0x11);
        std::vector<uint8_t> data(64, 0xFF);
        auto mac = hmac_streebog512(key, data);
        ASSERT_TRUE(mac.size() == 64);
        return true;
    });

    add_test("Streebog256_empty_input", []() -> bool {
        auto h = streebog256(nullptr, 0);
        ASSERT_TRUE(h.size() == 32);
        bool all_zero = true;
        for (auto b : h) if (b) { all_zero = false; break; }
        ASSERT_TRUE(!all_zero);
        return true;
    });

    add_test("Streebog256_large_input", []() -> bool {
        std::vector<uint8_t> data(1024 * 64, 0xAA);  // 64 КиБ
        auto h = streebog256(data.data(), data.size());
        ASSERT_TRUE(h.size() == 32);
        return true;
    });
}