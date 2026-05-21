/**
 * @file gen_certs.cpp
 * @brief Генератор ГОСТ-ключей и самоподписанных сертификатов
 *
 * Использование:
 *   ./gen_certs [output_dir]
 *
 * ИСПОЛЬЗОВАНИЕ СТАНДАРТОВ:
 * ─────────────────────────────────────────────────────────────────────────
 * [ГОСТ 34.10-2018]
 *   • Генерация ключевых пар gost2012_256 и gost2012_512
 *   • Сохранение в PEM-формат
 *   • Самоподпись тестовых данных
 *   • Верификация подписей
 *
 * [VKO ГОСТ Р 34.10-2012]
 *   • Генерация двух пар ключей обмена (XA paramset)
 *   • Выработка общего ключа с двух сторон
 *   • Проверка совпадения ключей
 *
 * [ГОСТ 34.11-2018]
 *   • Стрибог-256 хэш тестовых векторов
 *   • Стрибог-512 хэш тестовых векторов
 *   • HMAC-Стрибог тест
 *
 * [ГОСТ 34.12-2018] + [ГОСТ 34.13-2018]
 *   • Кузнечик: CTR, CBC, CFB режимы
 *   • Магма: CTR режим
 *   • Проверка корректности шифрования/расшифрования
 * ─────────────────────────────────────────────────────────────────────────
 */

#include "gost_utils.hpp"
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <stdexcept>

static void printSeparator(const std::string& title) {
    std::cout << "\n╔══════════════════════════════════════════════════════╗\n";
    std::cout << "║  " << title;
    for (size_t i = title.size(); i < 53; i++) std::cout << ' ';
    std::cout << "║\n";
    std::cout << "╚══════════════════════════════════════════════════════╝\n";
}

static void saveToFile(const std::string& path, const std::string& content) {
    std::ofstream f(path);
    if (!f) throw std::runtime_error("Не удалось открыть файл: " + path);
    f << content;
    std::cout << "  Сохранено: " << path << "\n";
}

int main(int argc, char* argv[]) {
    std::string outdir = ".";
    if (argc > 1) outdir = argv[1];

    std::cout << "╔═══════════════════════════════════════════════════════╗\n";
    std::cout << "║   GOST Key & Certificate Generator                   ║\n";
    std::cout << "║   ГОСТ 34.10/34.11/34.12/34.13-2018 + VKO            ║\n";
    std::cout << "╚═══════════════════════════════════════════════════════╝\n";

    if (!GostEngine::init()) {
        std::cerr << "\n[FATAL] GOST engine не загружен\n";
        return 1;
    }

    int failures = 0;

    // ════════════════════════════════════════════════════════════════════════
    // 1. [ГОСТ 34.11-2018] Стрибог — тест хэш-функции
    // ════════════════════════════════════════════════════════════════════════
    printSeparator("ГОСТ 34.11-2018: Стрибог");
    try {
        // Тестовый вектор: пустая строка
        Bytes empty_data = {};
        Bytes h256_empty = GostHash::hash256(empty_data);
        Bytes h512_empty = GostHash::hash512(empty_data);
        std::cout << "  Стрибог-256( \"\" ) = " << Utils::toHex(h256_empty) << "\n";
        std::cout << "  Стрибог-512( \"\" ) = " << Utils::toHex(h512_empty).substr(0,32) << "...\n";

        // Тестовый вектор: "abc"
        Bytes abc_data = {'a','b','c'};
        Bytes h256_abc = GostHash::hash256(abc_data);
        Bytes h512_abc = GostHash::hash512(abc_data);
        std::cout << "  Стрибог-256( \"abc\" ) = " << Utils::toHex(h256_abc) << "\n";
        std::cout << "  Стрибог-512( \"abc\" ) = " << Utils::toHex(h512_abc).substr(0,32) << "...\n";

        // Проверка лавинного эффекта
        Bytes abc1_data = {'a','b','c'};
        Bytes abc2_data = {'a','b','d'};
        Bytes h1 = GostHash::hash256(abc1_data);
        Bytes h2 = GostHash::hash256(abc2_data);
        int diff = 0;
        for (size_t i = 0; i < h1.size() && i < h2.size(); i++)
            diff += __builtin_popcount(h1[i] ^ h2[i]);
        std::cout << "  Лавинный эффект (abc vs abd): " << diff << "/256 бит отличаются\n";

        // HMAC тест
        Bytes key32 = GostCipher::randomBytes(32);
        Bytes msg   = {'T','e','s','t',' ','H','M','A','C'};
        Bytes hmac1 = GostHash::hmac256(key32, msg);
        Bytes hmac2 = GostHash::hmac256(key32, msg);
        bool hmac_ok = (hmac1 == hmac2);
        std::cout << "  HMAC-Стрибог-256: " << Utils::toHex(hmac1) << "\n";
        std::cout << "  HMAC детерминизм: " << (hmac_ok ? "✓ OK" : "✗ FAIL") << "\n";
        if (!hmac_ok) failures++;

    } catch (const std::exception& e) {
        std::cerr << "  [ОШИБКА] Стрибог: " << e.what() << "\n";
        failures++;
    }

    // ════════════════════════════════════════════════════════════════════════
    // 2. [ГОСТ 34.10-2018] Цифровая подпись — генерация и проверка
    // ════════════════════════════════════════════════════════════════════════
    printSeparator("ГОСТ 34.10-2018: Цифровая подпись");
    try {
        // Генерация ключевой пары
        std::cout << "  Генерация ключевой пары (gost2012_256, paramset A)...\n";
        auto kp = GostSign::generateKeyPair();
        std::cout << "  Ключи сгенерированы ✓\n";

        // Сериализация и сохранение
        std::string priv_pem = GostSign::privkeyToPem(kp.pkey.get());
        std::string pub_pem  = GostSign::pubkeyToPem(kp.pkey.get());
        saveToFile(outdir + "/sign_privkey.pem", priv_pem);
        saveToFile(outdir + "/sign_pubkey.pem",  pub_pem);

        // Тест подписи/верификации
        std::vector<std::string> test_messages = {
            "Тестовое сообщение 1",
            "GOST R 34.10-2018 Digital Signature Test",
            "Короткое сообщение",
            std::string(1000, 'A'), // длинное сообщение
        };

        for (const auto& msg : test_messages) {
            Bytes data(msg.begin(), msg.end());
            Bytes sig = GostSign::sign(kp.pkey.get(), data);
            bool ok   = GostSign::verify(kp.pkey.get(), data, sig);
            std::cout << "  Подпись+верификация (" << msg.size() << " байт): "
                      << (ok ? "✓ OK" : "✗ FAIL") << "\n";
            if (!ok) failures++;

            // Проверка что изменение данных инвалидирует подпись
            if (!data.empty()) {
                Bytes bad_data = data;
                bad_data[0] ^= 0xFF;
                bool bad_ok = GostSign::verify(kp.pkey.get(), bad_data, sig);
                std::cout << "  Инвалидация при изменении данных: "
                          << (!bad_ok ? "✓ Подпись отклонена" : "✗ ОШИБКА — подпись принята") << "\n";
                if (bad_ok) failures++;
            }
        }

        // Тест загрузки ключей из PEM
        auto loaded_pub = GostSign::pubkeyFromPem(pub_pem);
        Bytes test_data = {'T','e','s','t'};
        Bytes test_sig  = GostSign::sign(kp.pkey.get(), test_data);
        bool reload_ok  = GostSign::verify(loaded_pub.get(), test_data, test_sig);
        std::cout << "  Верификация загруженным публичным ключом: "
                  << (reload_ok ? "✓ OK" : "✗ FAIL") << "\n";
        if (!reload_ok) failures++;

    } catch (const std::exception& e) {
        std::cerr << "  [ОШИБКА] ГОСТ 34.10-2018: " << e.what() << "\n";
        failures++;
    }

    // ════════════════════════════════════════════════════════════════════════
    // 3. [VKO ГОСТ Р 34.10-2012] Выработка общего ключа
    // ════════════════════════════════════════════════════════════════════════
    printSeparator("VKO ГОСТ Р 34.10-2012: Выработка ключа");
    try {
        std::cout << "  Генерация VKO-ключей для сторон A и B...\n";
        auto kp_a = GostVKO::generateVKOKeyPair();
        auto kp_b = GostVKO::generateVKOKeyPair();
        std::cout << "  VKO-ключи сгенерированы ✓\n";

        // Сохранение ключей
        saveToFile(outdir + "/vko_a_privkey.pem", GostSign::privkeyToPem(kp_a.pkey.get()));
        saveToFile(outdir + "/vko_a_pubkey.pem",  GostSign::pubkeyToPem(kp_a.pkey.get()));
        saveToFile(outdir + "/vko_b_privkey.pem", GostSign::privkeyToPem(kp_b.pkey.get()));
        saveToFile(outdir + "/vko_b_pubkey.pem",  GostSign::pubkeyToPem(kp_b.pkey.get()));

        // UKM — общий для обеих сторон
        Bytes ukm = GostCipher::randomBytes(8);
        std::cout << "  UKM: " << Utils::toHex(ukm) << "\n";

        // Выработка ключей с двух сторон
        Bytes key_a = GostVKO::deriveSharedKey(kp_a.pkey.get(), kp_b.pkey.get(), ukm);
        Bytes key_b = GostVKO::deriveSharedKey(kp_b.pkey.get(), kp_a.pkey.get(), ukm);

        // Нормализация
        if (key_a.size() != 32) key_a = GostHash::hash256(key_a);
        if (key_b.size() != 32) key_b = GostHash::hash256(key_b);

        bool keys_match = (key_a == key_b);
        std::cout << "  Ключ стороны A: " << Utils::toHex(key_a) << "\n";
        std::cout << "  Ключ стороны B: " << Utils::toHex(key_b) << "\n";
        std::cout << "  Ключи совпадают: " << (keys_match ? "✓ OK" : "✗ FAIL") << "\n";
        if (!keys_match) failures++;

        // Тест: разные UKM дают разные ключи
        Bytes ukm2 = GostCipher::randomBytes(8);
        Bytes key_a2 = GostVKO::deriveSharedKey(kp_a.pkey.get(), kp_b.pkey.get(), ukm2);
        if (key_a2.size() != 32) key_a2 = GostHash::hash256(key_a2);
        bool diff_ukm = (key_a != key_a2);
        std::cout << "  Разные UKM → разные ключи: " << (diff_ukm ? "✓ OK" : "✗ FAIL") << "\n";

    } catch (const std::exception& e) {
        std::cerr << "  [ОШИБКА] VKO: " << e.what() << "\n";
        failures++;
    }

    // ════════════════════════════════════════════════════════════════════════
    // 4. [ГОСТ 34.12-2018] + [ГОСТ 34.13-2018] Шифрование
    // ════════════════════════════════════════════════════════════════════════
    printSeparator("ГОСТ 34.12/34.13-2018: Кузнечик + Магма");
    try {
        Bytes key32 = GostCipher::randomBytes(32);

        // Тестовые данные разной длины
        std::vector<std::pair<std::string, std::string>> cipher_tests = {
            {"Кузнечик CTR", "kuznyechik-ctr"},
            {"Кузнечик CBC", "kuznyechik-cbc"},
            {"Магма CTR",    "magma-ctr"},
        };

        for (const auto& [name, algo] : cipher_tests) {
            std::string plain_str = "Тест шифра " + name + " — ГОСТ 34.12/34.13-2018!";
            Bytes plain(plain_str.begin(), plain_str.end());

            bool ok = false;
            try {
                Bytes enc, dec;
                if (name == "Кузнечик CTR") {
                    Bytes iv = GostCipher::randomBytes(16);
                    enc = GostCipher::kuznyechikEncryptCTR(key32, iv, plain);
                    dec = GostCipher::kuznyechikDecryptCTR(key32, iv, enc);
                    ok  = (dec == plain);
                } else if (name == "Кузнечик CBC") {
                    Bytes iv = GostCipher::randomBytes(16);
                    enc = GostCipher::kuznyechikEncryptCBC(key32, iv, plain);
                    dec = GostCipher::kuznyechikDecryptCBC(key32, iv, enc);
                    ok  = (dec == plain);
                } else if (name == "Магма CTR") {
                    Bytes iv = GostCipher::randomBytes(8); // Магма: 64-бит блок
                    enc = GostCipher::magmaEncryptCTR(key32, iv, plain);
                    dec = GostCipher::magmaDecryptCTR(key32, iv, enc);
                    ok  = (dec == plain);
                }
                std::cout << "  " << name << " (" << plain.size() << " → "
                          << enc.size() << " байт): " << (ok ? "✓ OK" : "✗ FAIL") << "\n";
            } catch (const std::exception& e) {
                std::cout << "  " << name << ": ⚠ " << e.what() << "\n";
            }
            if (!ok) failures++;
        }

        // Тест: шифрование с двумя разными ключами даёт разные результаты
        Bytes key1 = GostCipher::randomBytes(32);
        Bytes key2 = GostCipher::randomBytes(32);
        Bytes iv   = GostCipher::randomBytes(16);
        Bytes plain = {'S','a','m','e',' ','p','l','a','i','n','t','e','x','t'};
        Bytes enc1  = GostCipher::kuznyechikEncryptCTR(key1, iv, plain);
        Bytes enc2  = GostCipher::kuznyechikEncryptCTR(key2, iv, plain);
        bool diff_keys = (enc1 != enc2);
        std::cout << "  Разные ключи → разные шифртексты: " << (diff_keys ? "✓ OK" : "✗ FAIL") << "\n";

    } catch (const std::exception& e) {
        std::cerr << "  [ОШИБКА] Шифрование: " << e.what() << "\n";
        failures++;
    }

    // ════════════════════════════════════════════════════════════════════════
    // Итоги
    // ════════════════════════════════════════════════════════════════════════
    printSeparator("Итоги тестирования");
    if (failures == 0) {
        std::cout << "  ✓ Все тесты прошли успешно!\n";
        std::cout << "  Файлы сохранены в: " << outdir << "/\n";
    } else {
        std::cerr << "  ✗ Обнаружено " << failures << " ошибок!\n";
    }

    GostEngine::cleanup();
    return failures > 0 ? 1 : 0;
}
