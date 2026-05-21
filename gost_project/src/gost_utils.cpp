/**
 * @file gost_utils.cpp
 * @brief Реализация утилит ГОСТ через OpenSSL + gost-engine
 *
 * КАРТА ИСПОЛЬЗОВАНИЯ СТАНДАРТОВ:
 * ══════════════════════════════════════════════════════════════════════════
 *
 * [ГОСТ 34.11-2018] «Стрибог» — хэш-функция
 *   • EVP_get_digestbyname("md_gost12_256") → Стрибог-256
 *   • EVP_get_digestbyname("md_gost12_512") → Стрибог-512
 *   • Используется в: GostHash::hash256(), hash512(), hmac256()
 *   • Также неявно в: GostSign::sign()/verify() как дайджест для ЭЦП
 *
 * [ГОСТ 34.10-2018] — Цифровая подпись на ЭК
 *   • EVP_PKEY_CTX_new_id(EVP_PKEY_EC, engine)  — создание контекста
 *   • EVP_PKEY_keygen() с алгоритмом gost2012_256 — генерация ключей
 *   • EVP_DigestSignInit / EVP_DigestSign        — формирование подписи
 *   • EVP_DigestVerifyInit / EVP_DigestVerify    — верификация подписи
 *   • Используется в: GostSign::generateKeyPair(), sign(), verify()
 *
 * [VKO ГОСТ Р 34.10-2012] — Выработка общего ключа (Key Agreement)
 *   • EVP_PKEY_derive_init / EVP_PKEY_derive     — протокол VKO
 *   • EVP_PKEY_CTX_ctrl(…, EVP_PKEY_CTRL_SET_IV, …) — установка UKM
 *   • paramset XA (ключи для обмена, не для подписи)
 *   • Используется в: GostVKO::deriveSharedKey(), generateVKOKeyPair()
 *
 * [ГОСТ 34.12-2018] — Блочные шифры Кузнечик (128-бит) и Магма (64-бит)
 *   • EVP_get_cipherbyname("kuznyechik-ctr") — Кузнечик CTR
 *   • EVP_get_cipherbyname("kuznyechik-cbc") — Кузнечик CBC
 *   • EVP_get_cipherbyname("magma-ctr")      — Магма CTR
 *   • Используется в: GostCipher::kuznyechikEncrypt*(), magmaEncrypt*()
 *
 * [ГОСТ 34.13-2018] — Режимы работы блочных шифров
 *   • CTR (счётчик): kuznyechik-ctr, magma-ctr
 *   • CBC (сцепление блоков): kuznyechik-cbc
 *   • EVP_EncryptInit_ex / EVP_EncryptUpdate / EVP_EncryptFinal_ex
 *   • Используется в: GostCipher (все функции шифрования)
 * ══════════════════════════════════════════════════════════════════════════
 */

#include "gost_utils.hpp"

#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <iostream>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <cstring>

// ─── Глобальный указатель на gost-engine ─────────────────────────────────────
static ENGINE* g_gost_engine = nullptr;

// ─── Вспомогательные функции ─────────────────────────────────────────────────
namespace Utils {

std::string toHex(const Bytes& b) {
    std::ostringstream ss;
    for (auto c : b)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)(unsigned char)c;
    return ss.str();
}

Bytes fromHex(const std::string& hex) {
    Bytes result;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        unsigned int byte;
        std::istringstream ss(hex.substr(i, 2));
        ss >> std::hex >> byte;
        result.push_back(static_cast<unsigned char>(byte));
    }
    return result;
}

std::string printOpenSSLErrors() {
    std::ostringstream ss;
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        ss << buf << "\n";
    }
    return ss.str();
}

} // namespace Utils

// ─── GostEngine ──────────────────────────────────────────────────────────────
namespace GostEngine {

bool init() {
    // Загрузка конфигурации OpenSSL (читает openssl.cnf)
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, nullptr);
    ERR_clear_error();

    // Попытка 1: взять из уже загруженных (через openssl.cnf)
    g_gost_engine = ENGINE_by_id("gost");
    if (g_gost_engine) {
        if (!ENGINE_init(g_gost_engine)) {
            ENGINE_free(g_gost_engine);
            g_gost_engine = nullptr;
        }
    }

    // Попытка 2: загрузить динамически по стандартным путям
    if (!g_gost_engine) {
        // Список возможных путей к .so/.dylib gost-engine
        const char* paths[] = {
            "gost",   // по имени (если в пути OpenSSL engines)
            "/usr/lib/x86_64-linux-gnu/engines-3/gost.so",
            "/usr/lib/x86_64-linux-gnu/engines-1.1/gost.so",
            "/usr/lib/engines-3/gost.so",
            "/usr/lib/engines-1.1/gost.so",
            "/usr/local/lib/engines-3/gost.so",
            "/usr/lib64/engines-3/gost.so",
            "/usr/local/lib/engines/gost.so",
            nullptr
        };

        for (int i = 0; paths[i]; ++i) {
            ENGINE* dyn = ENGINE_by_id("dynamic");
            if (!dyn) continue;
            ENGINE_ctrl_cmd_string(dyn, "SO_PATH", paths[i], 0);
            ENGINE_ctrl_cmd_string(dyn, "LOAD", nullptr, 0);
            ENGINE* candidate = ENGINE_by_id("gost");
            ENGINE_free(dyn);
            if (candidate) {
                if (ENGINE_init(candidate)) {
                    g_gost_engine = candidate;
                    break;
                }
                ENGINE_free(candidate);
            }
        }
    }

    if (!g_gost_engine) {
        std::cerr << "[WARN] GOST engine не загружен. "
                  << "Убедитесь, что openssl-gost-engine установлен и настроен в openssl.cnf\n";
        std::cerr << "[WARN] OpenSSL errors: " << Utils::printOpenSSLErrors() << "\n";
        return false;
    }

    // Регистрируем алгоритмы движка как дефолтные
    ENGINE_set_default(g_gost_engine, ENGINE_METHOD_ALL);
    std::cout << "[INFO] GOST engine загружен: " << ENGINE_get_name(g_gost_engine) << "\n";
    return true;
}

void cleanup() {
    if (g_gost_engine) {
        ENGINE_finish(g_gost_engine);
        ENGINE_free(g_gost_engine);
        g_gost_engine = nullptr;
    }
    ENGINE_cleanup();
}

ENGINE* get() {
    return g_gost_engine;
}

} // namespace GostEngine

// ─── GostHash — ГОСТ 34.11-2018 «Стрибог» ───────────────────────────────────
namespace GostHash {

/**
 * Внутренняя функция: вычисляет хэш указанным дайджест-алгоритмом.
 *
 * [ГОСТ 34.11-2018] Алгоритм «Стрибог»:
 *   - md_gost12_256 → Стрибог-256 (256-бит выход)
 *   - md_gost12_512 → Стрибог-512 (512-бит выход)
 */
static Bytes computeHash(const char* algo_name, const Bytes& data) {
    // [ГОСТ 34.11-2018] Получение указателя на алгоритм Стрибог
    const EVP_MD* md = EVP_get_digestbyname(algo_name);
    if (!md) {
        // Попытка найти через engine напрямую
        if (GostEngine::get())
            md = ENGINE_get_digest(GostEngine::get(), NID_undef);
        if (!md)
            throw std::runtime_error(std::string("Дайджест не найден: ") + algo_name
                                     + "\n" + Utils::printOpenSSLErrors());
    }

    EvpMdCtxPtr ctx(EVP_MD_CTX_new());
    if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");

    // [ГОСТ 34.11-2018] Инициализация контекста хэширования
    if (EVP_DigestInit_ex(ctx.get(), md, GostEngine::get()) != 1)
        throw std::runtime_error("EVP_DigestInit_ex: " + Utils::printOpenSSLErrors());

    // [ГОСТ 34.11-2018] Обработка входных данных
    if (EVP_DigestUpdate(ctx.get(), data.data(), data.size()) != 1)
        throw std::runtime_error("EVP_DigestUpdate: " + Utils::printOpenSSLErrors());

    // [ГОСТ 34.11-2018] Финализация — получение значения хэша
    Bytes digest(EVP_MD_size(md));
    unsigned int dlen = 0;
    if (EVP_DigestFinal_ex(ctx.get(), digest.data(), &dlen) != 1)
        throw std::runtime_error("EVP_DigestFinal_ex: " + Utils::printOpenSSLErrors());

    digest.resize(dlen);
    return digest;
}

// [ГОСТ 34.11-2018] Стрибог-256
Bytes hash256(const Bytes& data) {
    return computeHash("md_gost12_256", data);
}

// [ГОСТ 34.11-2018] Стрибог-512
Bytes hash512(const Bytes& data) {
    return computeHash("md_gost12_512", data);
}

// [ГОСТ 34.11-2018] HMAC-Стрибог-256
Bytes hmac256(const Bytes& key, const Bytes& data) {
    const EVP_MD* md = EVP_get_digestbyname("md_gost12_256");
    if (!md)
        throw std::runtime_error("HMAC: md_gost12_256 не найден. " + Utils::printOpenSSLErrors());

    Bytes result(EVP_MD_size(md));
    unsigned int rlen = 0;

    // [ГОСТ 34.11-2018] HMAC на базе Стрибог-256
    unsigned char* hmac_res = HMAC(
        md,
        key.data(), static_cast<int>(key.size()),
        data.data(), data.size(),
        result.data(), &rlen
    );

    if (!hmac_res)
        throw std::runtime_error("HMAC failed: " + Utils::printOpenSSLErrors());

    result.resize(rlen);
    return result;
}

} // namespace GostHash

// ─── GostSign — ГОСТ 34.10-2018 ─────────────────────────────────────────────
namespace GostSign {

/**
 * [ГОСТ 34.10-2018] Генерация пары ключей gost2012_256, paramset A.
 * Paramset A — стандартный набор параметров для цифровой подписи 256-бит.
 */
KeyPair generateKeyPair() {
    // [ГОСТ 34.10-2018] Создание контекста генератора ключей
    EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new_id(NID_undef, GostEngine::get()));

    // Пробуем получить NID для gost2012_256
    int nid = OBJ_txt2nid("gost2012_256");
    if (nid == NID_undef)
        nid = OBJ_txt2nid("id-GostR3410-2012-256");

    if (nid == NID_undef)
        throw std::runtime_error("NID для gost2012_256 не найден. "
                                 "Проверьте загрузку gost-engine.\n"
                                 + Utils::printOpenSSLErrors());

    ctx.reset(EVP_PKEY_CTX_new_id(nid, GostEngine::get()));
    if (!ctx)
        throw std::runtime_error("EVP_PKEY_CTX_new_id(gost2012_256): "
                                 + Utils::printOpenSSLErrors());

    // [ГОСТ 34.10-2018] Инициализация генерации ключей
    if (EVP_PKEY_keygen_init(ctx.get()) != 1)
        throw std::runtime_error("EVP_PKEY_keygen_init: " + Utils::printOpenSSLErrors());

    // [ГОСТ 34.10-2018] Установка paramset A (параметры кривой для ЭЦП)
    if (EVP_PKEY_CTX_ctrl_str(ctx.get(), "paramset", "A") != 1)
        throw std::runtime_error("EVP_PKEY_CTX_ctrl_str(paramset=A): "
                                 + Utils::printOpenSSLErrors());

    // [ГОСТ 34.10-2018] Генерация ключевой пары
    EVP_PKEY* pkey_raw = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &pkey_raw) != 1)
        throw std::runtime_error("EVP_PKEY_keygen: " + Utils::printOpenSSLErrors());

    KeyPair kp;
    kp.pkey.reset(pkey_raw);
    return kp;
}

/**
 * [ГОСТ 34.10-2018] Подпись данных.
 * Используется дайджест: md_gost12_256 [ГОСТ 34.11-2018].
 */
Bytes sign(EVP_PKEY* key, const Bytes& data) {
    // [ГОСТ 34.11-2018] Получение дайджеста Стрибог-256 для использования в ЭЦП
    const EVP_MD* md = EVP_get_digestbyname("md_gost12_256");
    if (!md)
        throw std::runtime_error("sign: md_gost12_256 не найден");

    EvpMdCtxPtr ctx(EVP_MD_CTX_new());
    if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");

    // [ГОСТ 34.10-2018] Инициализация контекста подписи
    // Внутри: хэширование по [ГОСТ 34.11-2018], подпись по [ГОСТ 34.10-2018]
    if (EVP_DigestSignInit(ctx.get(), nullptr, md, GostEngine::get(), key) != 1)
        throw std::runtime_error("EVP_DigestSignInit: " + Utils::printOpenSSLErrors());

    // [ГОСТ 34.10-2018] Обработка данных
    if (EVP_DigestSignUpdate(ctx.get(), data.data(), data.size()) != 1)
        throw std::runtime_error("EVP_DigestSignUpdate: " + Utils::printOpenSSLErrors());

    // [ГОСТ 34.10-2018] Получение размера подписи
    size_t sig_len = 0;
    if (EVP_DigestSignFinal(ctx.get(), nullptr, &sig_len) != 1)
        throw std::runtime_error("EVP_DigestSignFinal (size): " + Utils::printOpenSSLErrors());

    // [ГОСТ 34.10-2018] Генерация подписи
    Bytes signature(sig_len);
    if (EVP_DigestSignFinal(ctx.get(), signature.data(), &sig_len) != 1)
        throw std::runtime_error("EVP_DigestSignFinal: " + Utils::printOpenSSLErrors());

    signature.resize(sig_len);
    return signature;
}

/**
 * [ГОСТ 34.10-2018] Верификация подписи.
 * Использует Стрибог-256 [ГОСТ 34.11-2018] как дайджест.
 */
bool verify(EVP_PKEY* pubkey, const Bytes& data, const Bytes& signature) {
    const EVP_MD* md = EVP_get_digestbyname("md_gost12_256");
    if (!md)
        throw std::runtime_error("verify: md_gost12_256 не найден");

    EvpMdCtxPtr ctx(EVP_MD_CTX_new());
    if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");

    // [ГОСТ 34.10-2018] Инициализация контекста верификации
    if (EVP_DigestVerifyInit(ctx.get(), nullptr, md, GostEngine::get(), pubkey) != 1)
        throw std::runtime_error("EVP_DigestVerifyInit: " + Utils::printOpenSSLErrors());

    // [ГОСТ 34.10-2018] Обработка данных
    if (EVP_DigestVerifyUpdate(ctx.get(), data.data(), data.size()) != 1)
        throw std::runtime_error("EVP_DigestVerifyUpdate: " + Utils::printOpenSSLErrors());

    // [ГОСТ 34.10-2018] Верификация подписи
    int result = EVP_DigestVerifyFinal(ctx.get(), signature.data(), signature.size());
    if (result < 0)
        throw std::runtime_error("EVP_DigestVerifyFinal error: " + Utils::printOpenSSLErrors());
    return result == 1;
}

std::string pubkeyToPem(EVP_PKEY* pkey) {
    BioPtr bio(BIO_new(BIO_s_mem()));
    if (!PEM_write_bio_PUBKEY(bio.get(), pkey))
        throw std::runtime_error("PEM_write_bio_PUBKEY: " + Utils::printOpenSSLErrors());
    BUF_MEM* bptr;
    BIO_get_mem_ptr(bio.get(), &bptr);
    return std::string(bptr->data, bptr->length);
}

EvpPkeyPtr pubkeyFromPem(const std::string& pem) {
    BioPtr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr);
    if (!pkey)
        throw std::runtime_error("PEM_read_bio_PUBKEY: " + Utils::printOpenSSLErrors());
    return EvpPkeyPtr(pkey);
}

std::string privkeyToPem(EVP_PKEY* pkey) {
    BioPtr bio(BIO_new(BIO_s_mem()));
    if (!PEM_write_bio_PrivateKey(bio.get(), pkey, nullptr, nullptr, 0, nullptr, nullptr))
        throw std::runtime_error("PEM_write_bio_PrivateKey: " + Utils::printOpenSSLErrors());
    BUF_MEM* bptr;
    BIO_get_mem_ptr(bio.get(), &bptr);
    return std::string(bptr->data, bptr->length);
}

EvpPkeyPtr privkeyFromPem(const std::string& pem) {
    BioPtr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr);
    if (!pkey)
        throw std::runtime_error("PEM_read_bio_PrivateKey: " + Utils::printOpenSSLErrors());
    return EvpPkeyPtr(pkey);
}

} // namespace GostSign

// ─── GostVKO — VKO ГОСТ Р 34.10-2012 ────────────────────────────────────────
namespace GostVKO {

/**
 * [VKO ГОСТ Р 34.10-2012] Генерация ключей для обмена (paramset XA).
 * XA/XB — параметры, предназначенные именно для Key Exchange (не для подписи).
 */
GostSign::KeyPair generateVKOKeyPair() {
    int nid = OBJ_txt2nid("gost2012_256");
    if (nid == NID_undef)
        nid = OBJ_txt2nid("id-GostR3410-2012-256");
    if (nid == NID_undef)
        throw std::runtime_error("NID gost2012_256 не найден");

    EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new_id(nid, GostEngine::get()));
    if (!ctx)
        throw std::runtime_error("VKO keygen ctx: " + Utils::printOpenSSLErrors());

    if (EVP_PKEY_keygen_init(ctx.get()) != 1)
        throw std::runtime_error("VKO keygen_init: " + Utils::printOpenSSLErrors());

    // [VKO ГОСТ Р 34.10-2012] Paramset XA — параметры для Key Exchange
    if (EVP_PKEY_CTX_ctrl_str(ctx.get(), "paramset", "XA") != 1) {
        // Если XA не поддерживается — используем A
        EVP_PKEY_CTX_ctrl_str(ctx.get(), "paramset", "A");
    }

    EVP_PKEY* pkey_raw = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &pkey_raw) != 1)
        throw std::runtime_error("VKO keygen: " + Utils::printOpenSSLErrors());

    GostSign::KeyPair kp;
    kp.pkey.reset(pkey_raw);
    return kp;
}

/**
 * [VKO ГОСТ Р 34.10-2012] Выработка общего секрета.
 * Протокол: Ephemeral Diffie-Hellman на ГОСТ-кривых.
 * UKM (User Keying Material) — 8 байт случайных данных, должен быть
 * передан другой стороне для воспроизводимости результата.
 *
 * RFC 7836: результат — 32 байта ключа для симметричного шифрования.
 */
Bytes deriveSharedKey(EVP_PKEY* myPrivkey, EVP_PKEY* peerPubkey, const Bytes& ukm) {
    if (ukm.size() != 8)
        throw std::invalid_argument("UKM должен быть ровно 8 байт (VKO ГОСТ Р 34.10-2012)");

    // [VKO ГОСТ Р 34.10-2012] Создание контекста выработки ключа
    EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new(myPrivkey, GostEngine::get()));
    if (!ctx)
        throw std::runtime_error("VKO derive ctx: " + Utils::printOpenSSLErrors());

    // [VKO ГОСТ Р 34.10-2012] Инициализация протокола VKO
    if (EVP_PKEY_derive_init(ctx.get()) != 1)
        throw std::runtime_error("VKO derive_init: " + Utils::printOpenSSLErrors());

    // [VKO ГОСТ Р 34.10-2012] Установка UKM (User Keying Material)
    // UKM влияет на результирующий ключ — обе стороны должны использовать одинаковый UKM
    if (EVP_PKEY_CTX_ctrl(ctx.get(), -1, EVP_PKEY_OP_DERIVE,
                          EVP_PKEY_CTRL_SET_IV,
                          static_cast<int>(ukm.size()),
                          const_cast<unsigned char*>(ukm.data())) <= 0) {
        // Некоторые версии используют другой control code
        std::cerr << "[WARN] VKO: EVP_PKEY_CTRL_SET_IV не поддержан, продолжаем без UKM\n";
    }

    // [VKO ГОСТ Р 34.10-2012] Установка публичного ключа партнёра
    if (EVP_PKEY_derive_set_peer(ctx.get(), peerPubkey) != 1)
        throw std::runtime_error("VKO derive_set_peer: " + Utils::printOpenSSLErrors());

    // [VKO ГОСТ Р 34.10-2012] Выработка общего ключа
    size_t key_len = 0;
    if (EVP_PKEY_derive(ctx.get(), nullptr, &key_len) != 1)
        throw std::runtime_error("VKO derive (size): " + Utils::printOpenSSLErrors());

    Bytes shared(key_len);
    if (EVP_PKEY_derive(ctx.get(), shared.data(), &key_len) != 1)
        throw std::runtime_error("VKO derive: " + Utils::printOpenSSLErrors());

    shared.resize(key_len);
    return shared;
}

} // namespace GostVKO

// ─── GostCipher — ГОСТ 34.12-2018 + ГОСТ 34.13-2018 ─────────────────────────
namespace GostCipher {

/**
 * Внутренняя функция шифрования/дешифрования.
 *
 * [ГОСТ 34.12-2018] Алгоритм шифра (Кузнечик или Магма).
 * [ГОСТ 34.13-2018] Режим работы (CTR, CBC, CFB, OFB).
 */
static Bytes cipherOperation(const char* cipher_name,
                              const Bytes& key, const Bytes& iv,
                              const Bytes& input, bool encrypt) {
    // [ГОСТ 34.12-2018 + ГОСТ 34.13-2018] Получение шифра по имени
    const EVP_CIPHER* cipher = EVP_get_cipherbyname(cipher_name);
    if (!cipher)
        throw std::runtime_error(std::string("Шифр не найден: ") + cipher_name
                                 + "\n" + Utils::printOpenSSLErrors());

    EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    // [ГОСТ 34.12-2018 + ГОСТ 34.13-2018] Инициализация контекста шифрования
    int ok = encrypt
        ? EVP_EncryptInit_ex(ctx.get(), cipher, GostEngine::get(), nullptr, nullptr)
        : EVP_DecryptInit_ex(ctx.get(), cipher, GostEngine::get(), nullptr, nullptr);
    if (!ok)
        throw std::runtime_error("CipherInit (pass1): " + Utils::printOpenSSLErrors());

    // Отключаем стандартный PKCS7-паддинг для CTR-режима (поток)
    EVP_CIPHER_CTX_set_padding(ctx.get(), 1);

    // Устанавливаем ключ и IV
    ok = encrypt
        ? EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.empty() ? nullptr : iv.data())
        : EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.empty() ? nullptr : iv.data());
    if (!ok)
        throw std::runtime_error("CipherInit (key/iv): " + Utils::printOpenSSLErrors());

    Bytes output(input.size() + EVP_CIPHER_block_size(cipher));
    int out_len = 0, final_len = 0;

    // [ГОСТ 34.13-2018] Обработка данных в выбранном режиме
    ok = encrypt
        ? EVP_EncryptUpdate(ctx.get(), output.data(), &out_len, input.data(), static_cast<int>(input.size()))
        : EVP_DecryptUpdate(ctx.get(), output.data(), &out_len, input.data(), static_cast<int>(input.size()));
    if (!ok)
        throw std::runtime_error("CipherUpdate: " + Utils::printOpenSSLErrors());

    // [ГОСТ 34.13-2018] Финализация
    ok = encrypt
        ? EVP_EncryptFinal_ex(ctx.get(), output.data() + out_len, &final_len)
        : EVP_DecryptFinal_ex(ctx.get(), output.data() + out_len, &final_len);
    if (!ok)
        throw std::runtime_error("CipherFinal: " + Utils::printOpenSSLErrors());

    output.resize(static_cast<size_t>(out_len + final_len));
    return output;
}

// [ГОСТ 34.12-2018 Кузнечик] + [ГОСТ 34.13-2018 режим CTR]
Bytes kuznyechikEncryptCTR(const Bytes& key, const Bytes& iv, const Bytes& data) {
    return cipherOperation("kuznyechik-ctr", key, iv, data, true);
}

Bytes kuznyechikDecryptCTR(const Bytes& key, const Bytes& iv, const Bytes& ciphertext) {
    return cipherOperation("kuznyechik-ctr", key, iv, ciphertext, false);
}

// [ГОСТ 34.12-2018 Кузнечик] + [ГОСТ 34.13-2018 режим CBC]
Bytes kuznyechikEncryptCBC(const Bytes& key, const Bytes& iv, const Bytes& data) {
    return cipherOperation("kuznyechik-cbc", key, iv, data, true);
}

Bytes kuznyechikDecryptCBC(const Bytes& key, const Bytes& iv, const Bytes& ciphertext) {
    return cipherOperation("kuznyechik-cbc", key, iv, ciphertext, false);
}

// [ГОСТ 34.12-2018 Магма] + [ГОСТ 34.13-2018 режим CTR]
Bytes magmaEncryptCTR(const Bytes& key, const Bytes& iv, const Bytes& data) {
    return cipherOperation("magma-ctr", key, iv, data, true);
}

Bytes magmaDecryptCTR(const Bytes& key, const Bytes& iv, const Bytes& ciphertext) {
    return cipherOperation("magma-ctr", key, iv, ciphertext, false);
}

Bytes randomBytes(size_t n) {
    Bytes buf(n);
    if (RAND_bytes(buf.data(), static_cast<int>(n)) != 1)
        throw std::runtime_error("RAND_bytes: " + Utils::printOpenSSLErrors());
    return buf;
}

} // namespace GostCipher
