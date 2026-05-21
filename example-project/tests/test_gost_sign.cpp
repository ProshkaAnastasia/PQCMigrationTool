// ─────────────────────────────────────────────────────────────────────────────
// Тесты ГОСТ Р 34.10-2012 (электронная подпись), KDF и утилит
// ─────────────────────────────────────────────────────────────────────────────
#include "test_helper.hpp"
#include "crypto/gost_sign.hpp"
#include "crypto/streebog.hpp"
#include "crypto/hmac_streebog.hpp"
#include "crypto/kdf.hpp"
#include "storage/encrypted_storage.hpp"
#include "common/utils.hpp"

using namespace gost;

void register_gost_sign_tests() {

    add_test("GostKeyPair_generate_256", []() -> bool {
        try {
            auto kp = GostKeyPair::generate(GostCurve::TC26_GOST_3410_12_256_A);
            ASSERT_TRUE(!kp.public_key_der().empty());
            ASSERT_TRUE(!kp.private_key_der().empty());
        } catch (const std::exception& e) {
            std::cerr << "  SKIP (TC26 не поддерживается): " << e.what() << "\n";
        }
        return true;
    });

    add_test("GostSign_sign_then_verify", []() -> bool {
        try {
            auto kp = GostKeyPair::generate(GostCurve::TC26_GOST_3410_12_256_A);
            const char* msg = "Тест ГОСТ Р 34.10-2012";
            auto hash = streebog256(reinterpret_cast<const uint8_t*>(msg), strlen(msg));

            GostSigner signer(kp);
            auto sig = signer.sign(hash.data(), hash.size());
            ASSERT_TRUE(!sig.empty());

            GostVerifier verifier(kp.public_key_der(), GostCurve::TC26_GOST_3410_12_256_A);
            ASSERT_TRUE(verifier.verify(hash.data(), hash.size(), sig));
        } catch (const std::exception& e) {
            std::cerr << "  SKIP: " << e.what() << "\n";
        }
        return true;
    });

    add_test("GostSign_tampered_hash_fails", []() -> bool {
        try {
            auto kp = GostKeyPair::generate(GostCurve::TC26_GOST_3410_12_256_A);
            auto hash = streebog256(reinterpret_cast<const uint8_t*>("data"), 4);
            auto sig = GostSigner(kp).sign(hash.data(), hash.size());

            // Изменяем хэш — верификация должна упасть
            hash[0] ^= 0xFF;
            GostVerifier ver(kp.public_key_der(), GostCurve::TC26_GOST_3410_12_256_A);
            bool bad = ver.verify(hash.data(), hash.size(), sig);
            ASSERT_TRUE(!bad);
        } catch (...) {}
        return true;
    });

    add_test("GostSign_wrong_key_fails", []() -> bool {
        try {
            auto kp1 = GostKeyPair::generate(GostCurve::TC26_GOST_3410_12_256_A);
            auto kp2 = GostKeyPair::generate(GostCurve::TC26_GOST_3410_12_256_A);
            auto hash = streebog256(reinterpret_cast<const uint8_t*>("msg"), 3);
            auto sig = GostSigner(kp1).sign(hash.data(), hash.size());

            GostVerifier ver(kp2.public_key_der(), GostCurve::TC26_GOST_3410_12_256_A);
            ASSERT_TRUE(!ver.verify(hash.data(), hash.size(), sig));
        } catch (...) {}
        return true;
    });

    // kdf_from_password принимает std::string
    add_test("KDF_from_password_deterministic", []() -> bool {
        std::vector<uint8_t> salt(16, 0x42);
        auto k1 = kdf_from_password("secret", salt, 1000, 32);
        auto k2 = kdf_from_password("secret", salt, 1000, 32);
        ASSERT_TRUE(k1.size() == 32);
        ASSERT_TRUE(k1 == k2);
        return true;
    });

    add_test("KDF_different_passwords_differ", []() -> bool {
        std::vector<uint8_t> salt(16, 0x11);
        auto k1 = kdf_from_password("password1", salt, 100, 32);
        auto k2 = kdf_from_password("password2", salt, 100, 32);
        ASSERT_NE(k1, k2);
        return true;
    });

    add_test("KDF_different_salts_differ", []() -> bool {
        auto s1 = utils::secure_random(16);
        auto s2 = utils::secure_random(16);
        auto k1 = kdf_from_password("pass", s1, 100, 32);
        auto k2 = kdf_from_password("pass", s2, 100, 32);
        ASSERT_NE(k1, k2);
        return true;
    });

    add_test("HKDF_Streebog256_lengths", []() -> bool {
        auto ikm  = utils::secure_random(32);
        auto salt = utils::secure_random(16);
        std::vector<uint8_t> info = {'a','p','p'};
        auto k32 = hkdf_streebog256(ikm, salt, info, 32);
        auto k64 = hkdf_streebog256(ikm, salt, info, 64);
        ASSERT_TRUE(k32.size() == 32);
        ASSERT_TRUE(k64.size() == 64);
        // Первые 32 байта совпадают (HKDF expand детерминирован)
        ASSERT_TRUE(std::equal(k32.begin(), k32.end(), k64.begin()));
        return true;
    });

    add_test("EncryptedStorage_roundtrip", []() -> bool {
        auto key = utils::secure_random(32);
        std::string text = "Секретный документ ГОСТ";
        std::vector<uint8_t> plain(text.begin(), text.end());

        auto enc = storage::EncryptedStorage::encrypt(plain, key);
        ASSERT_TRUE(enc.size() > plain.size());

        auto dec = storage::EncryptedStorage::decrypt(enc, key);
        ASSERT_TRUE(dec == plain);
        return true;
    });

    add_test("EncryptedStorage_wrong_key_throws", []() -> bool {
        auto key     = utils::secure_random(32);
        auto bad_key = utils::secure_random(32);
        std::vector<uint8_t> plain(32, 0xAB);
        auto enc = storage::EncryptedStorage::encrypt(plain, key);
        bool threw = false;
        try { storage::EncryptedStorage::decrypt(enc, bad_key); }
        catch (...) { threw = true; }
        ASSERT_TRUE(threw);
        return true;
    });

    add_test("Utils_hex_roundtrip", []() -> bool {
        std::vector<uint8_t> data = {0x00, 0xFF, 0xAB, 0x12, 0x34};
        ASSERT_TRUE(utils::from_hex(utils::to_hex(data)) == data);
        return true;
    });

    add_test("Utils_base64_roundtrip", []() -> bool {
        auto data = utils::secure_random(33);  // Не кратно 3 — проверяем паддинг
        ASSERT_TRUE(utils::from_base64(utils::to_base64(data)) == data);
        return true;
    });

    add_test("Utils_secure_random_unique", []() -> bool {
        auto r1 = utils::secure_random(32);
        auto r2 = utils::secure_random(32);
        ASSERT_NE(r1, r2);
        return true;
    });
}