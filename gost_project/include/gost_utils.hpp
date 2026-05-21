/**
 * @file gost_utils.hpp
 * @brief Утилиты для работы с ГОСТ-алгоритмами через OpenSSL + gost-engine
 *
 * ИСПОЛЬЗУЕМЫЕ СТАНДАРТЫ:
 * ──────────────────────────────────────────────────────────────────────────
 * ГОСТ 34.10-2018  — Цифровая подпись (ЭЦП) на эллиптических кривых
 *                    Алгоритм: gost2012_256 / gost2012_512
 *                    Функции: GostSign::generateKeyPair(), sign(), verify()
 *
 * VKO ГОСТ Р 34.10-2012 — Выработка общего ключа (Key Agreement)
 *                    RFC 7836 / RFC 4357
 *                    Алгоритм: EVP_PKEY_derive (gost2012_256 с парамсетом XA)
 *                    Функции: GostVKO::deriveSharedKey()
 *
 * ГОСТ 34.12-2018  — Блочные шифры Кузнечик (Grasshopper/Kuznyechik, 128-бит)
 *                    и Магма (Magma, 64-бит)
 *                    Алгоритмы: kuznyechik-ctr, magma-ctr, kuznyechik-cbc
 *                    Функции: GostCipher::encrypt(), decrypt()
 *
 * ГОСТ 34.13-2018  — Режимы работы блочных шифров (CTR, CBC, CFB, OFB, ECB)
 *                    Применяется совместно с ГОСТ 34.12-2018
 *                    Алгоритмы: kuznyechik-ctr, kuznyechik-cbc, kuznyechik-cfb
 *                    Функции: GostCipher::encryptCBC(), encryptCTR()
 *
 * ГОСТ 34.11-2018  — Хэш-функция «Стрибог» (Streebog)
 *                    Алгоритмы: md_gost12_256 (256-бит), md_gost12_512 (512-бит)
 *                    Функции: GostHash::hash256(), hash512(), hmac256()
 * ──────────────────────────────────────────────────────────────────────────
 */

#pragma once

#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <string>
#include <vector>
#include <stdexcept>
#include <memory>
#include <cstring>

// ─── Типы-обёртки ───────────────────────────────────────────────────────────
using Bytes = std::vector<unsigned char>;

// ─── Вспомогательные RAII-обёртки над OpenSSL объектами ─────────────────────
struct EvpMdCtxDeleter   { void operator()(EVP_MD_CTX*   p) const { EVP_MD_CTX_free(p);   } };
struct EvpPkeyCtxDeleter { void operator()(EVP_PKEY_CTX* p) const { EVP_PKEY_CTX_free(p); } };
struct EvpCipherCtxDel   { void operator()(EVP_CIPHER_CTX* p) const { EVP_CIPHER_CTX_free(p); } };
struct EvpPkeyDeleter    { void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); } };
struct BioDeleter        { void operator()(BIO* p) const { BIO_free_all(p); } };
struct X509Deleter       { void operator()(X509* p) const { X509_free(p); } };

using EvpMdCtxPtr    = std::unique_ptr<EVP_MD_CTX,    EvpMdCtxDeleter>;
using EvpPkeyCtxPtr  = std::unique_ptr<EVP_PKEY_CTX,  EvpPkeyCtxDeleter>;
using EvpCipherCtxPtr= std::unique_ptr<EVP_CIPHER_CTX,EvpCipherCtxDel>;
using EvpPkeyPtr     = std::unique_ptr<EVP_PKEY,      EvpPkeyDeleter>;
using BioPtr         = std::unique_ptr<BIO,           BioDeleter>;
using X509Ptr        = std::unique_ptr<X509,          X509Deleter>;

// ─── Инициализация GOST-engine ───────────────────────────────────────────────
namespace GostEngine {
    /**
     * Загружает gost-engine динамически.
     * Поддерживает OpenSSL 1.1.x и 3.x (через ENGINE API).
     * @throws std::runtime_error если движок не найден.
     */
    bool init();
    void cleanup();
    ENGINE* get();
}

// ─── ГОСТ 34.11-2018 — Хэш-функция «Стрибог» ────────────────────────────────
namespace GostHash {
    /**
     * Вычисляет хэш Стрибог-256 (ГОСТ 34.11-2018, 256-бит вариант).
     * @param data  Входные данные
     * @return      32 байта хэша
     */
    Bytes hash256(const Bytes& data);

    /**
     * Вычисляет хэш Стрибог-512 (ГОСТ 34.11-2018, 512-бит вариант).
     * @param data  Входные данные
     * @return      64 байта хэша
     */
    Bytes hash512(const Bytes& data);

    /**
     * Вычисляет HMAC на базе Стрибог-256 (ГОСТ 34.11-2018 + HMAC).
     * @param key   Ключ HMAC (произвольная длина)
     * @param data  Сообщение
     * @return      32 байта HMAC
     */
    Bytes hmac256(const Bytes& key, const Bytes& data);
}

// ─── ГОСТ 34.10-2018 — Цифровая подпись ─────────────────────────────────────
namespace GostSign {
    struct KeyPair {
        EvpPkeyPtr pkey; ///< содержит приватный + публичный ключ
    };

    /**
     * Генерирует пару ключей ГОСТ 34.10-2018 (gost2012_256, paramset A).
     * @return  KeyPair с EVP_PKEY внутри
     */
    KeyPair generateKeyPair();

    /**
     * Подписывает данные ключом ГОСТ 34.10-2018.
     * Хэш: Стрибог-256 (ГОСТ 34.11-2018).
     * @param key   Приватный ключ
     * @param data  Данные для подписи
     * @return      DER-кодированная подпись
     */
    Bytes sign(EVP_PKEY* key, const Bytes& data);

    /**
     * Верифицирует подпись ГОСТ 34.10-2018.
     * @param pubkey    Публичный ключ
     * @param data      Исходные данные
     * @param signature Подпись (DER)
     * @return          true если подпись верна
     */
    bool verify(EVP_PKEY* pubkey, const Bytes& data, const Bytes& signature);

    /**
     * Сериализует публичный ключ в PEM-строку.
     */
    std::string pubkeyToPem(EVP_PKEY* pkey);

    /**
     * Десериализует публичный ключ из PEM-строки.
     */
    EvpPkeyPtr pubkeyFromPem(const std::string& pem);

    /**
     * Сериализует приватный ключ в PEM-строку.
     */
    std::string privkeyToPem(EVP_PKEY* pkey);

    /**
     * Десериализует приватный ключ из PEM-строки.
     */
    EvpPkeyPtr privkeyFromPem(const std::string& pem);
}

// ─── VKO ГОСТ Р 34.10-2012 — Выработка общего ключа ────────────────────────
namespace GostVKO {
    /**
     * Вырабатывает общий секрет (Shared Key) по алгоритму VKO ГОСТ Р 34.10-2012.
     * RFC 7836, секция 5.2 — алгоритм KEK derivation.
     *
     * @param myPrivkey     Наш приватный ключ (gost2012_256, XA/XB paramset)
     * @param peerPubkey    Публичный ключ другой стороны
     * @param ukm           UKM (User Keying Material) — 8 байт случайных данных
     * @return              32 байта общего ключа
     */
    Bytes deriveSharedKey(EVP_PKEY* myPrivkey, EVP_PKEY* peerPubkey,
                          const Bytes& ukm);

    /**
     * Генерирует пару ключей для VKO (paramset XA — ключи обмена).
     */
    GostSign::KeyPair generateVKOKeyPair();
}

// ─── ГОСТ 34.12-2018 + ГОСТ 34.13-2018 — Шифрование ─────────────────────────
namespace GostCipher {
    /**
     * Шифрует данные алгоритмом Кузнечик (ГОСТ 34.12-2018) в режиме CTR
     * (ГОСТ 34.13-2018, режим счётчика).
     *
     * @param key   32 байта ключа (256 бит)
     * @param iv    16 байт IV/nonce (для CTR)
     * @param data  Открытый текст
     * @return      Шифртекст
     */
    Bytes kuznyechikEncryptCTR(const Bytes& key, const Bytes& iv, const Bytes& data);

    /**
     * Дешифрует данные Кузнечик CTR (ГОСТ 34.12-2018 + ГОСТ 34.13-2018).
     */
    Bytes kuznyechikDecryptCTR(const Bytes& key, const Bytes& iv, const Bytes& ciphertext);

    /**
     * Шифрует данные алгоритмом Кузнечик (ГОСТ 34.12-2018) в режиме CBC
     * (ГОСТ 34.13-2018, режим сцепления блоков).
     *
     * @param key   32 байта ключа (256 бит)
     * @param iv    16 байт IV
     * @param data  Открытый текст (будет дополнен паддингом)
     * @return      Шифртекст
     */
    Bytes kuznyechikEncryptCBC(const Bytes& key, const Bytes& iv, const Bytes& data);

    /**
     * Дешифрует данные Кузнечик CBC (ГОСТ 34.12-2018 + ГОСТ 34.13-2018).
     */
    Bytes kuznyechikDecryptCBC(const Bytes& key, const Bytes& iv, const Bytes& ciphertext);

    /**
     * Шифрует данные алгоритмом Магма (ГОСТ 34.12-2018, 64-бит блок) в режиме CTR.
     * (ГОСТ 34.13-2018, режим счётчика для Магма)
     *
     * @param key   32 байта ключа
     * @param iv    8 байт IV (64-бит, размер блока Магма)
     * @param data  Открытый текст
     * @return      Шифртекст
     */
    Bytes magmaEncryptCTR(const Bytes& key, const Bytes& iv, const Bytes& data);

    /**
     * Дешифрует данные Магма CTR (ГОСТ 34.12-2018 + ГОСТ 34.13-2018).
     */
    Bytes magmaDecryptCTR(const Bytes& key, const Bytes& iv, const Bytes& ciphertext);

    /**
     * Генерирует случайные байты с помощью OpenSSL PRNG.
     */
    Bytes randomBytes(size_t n);
}

// ─── Утилиты кодирования ─────────────────────────────────────────────────────
namespace Utils {
    std::string toHex(const Bytes& b);
    Bytes fromHex(const std::string& hex);
    std::string printOpenSSLErrors();
}
