// ─────────────────────────────────────────────────────────────────────────────
// Клиент / демо-приложение защищённого документооборота
//
// Запуск:  ./gost_client [--host H] [--port P] [--cert C] [--key K] [--ca CA]
//
// Без сертификатов (или с --demo): демонстрирует все ГОСТ алгоритмы.
// ─────────────────────────────────────────────────────────────────────────────
#include "network/tls_client.hpp"
#include "network/message_protocol.hpp"
#include "auth/authenticator.hpp"
#include "document/document_signer.hpp"
#include "document/document_verifier.hpp"
#include "crypto/gost_sign.hpp"
#include "crypto/streebog.hpp"
#include "crypto/hmac_streebog.hpp"
#include "crypto/grasshopper.hpp"
#include "crypto/kdf.hpp"
#include "storage/encrypted_storage.hpp"
#include "common/logger.hpp"
#include "common/utils.hpp"
#include <iostream>
#include <string>
#include <cstring>

using namespace gost;

struct ClientConfig {
    std::string host         = "127.0.0.1";
    uint16_t    port         = 8443;
    std::string cert_file    = "certs/client.crt";
    std::string key_file     = "certs/client.key";
    std::string ca_cert_file = "certs/ca.crt";
    std::string sign_file;
    bool demo_mode = false;
};

// ── Демо-режим ────────────────────────────────────────────────────────────────

static void run_demo() {
    LOG_INFO("Demo", "=== Демонстрация ГОСТ криптографии ===");

    // 1. Стрибог-256 / 512 (ГОСТ Р 34.11-2012)
    const char* msg = "Привет, ГОСТ!";
    auto h256 = streebog256(reinterpret_cast<const uint8_t*>(msg), strlen(msg));
    auto h512 = streebog512(reinterpret_cast<const uint8_t*>(msg), strlen(msg));
    LOG_INFO("Demo", "Стрибог-256: " + utils::to_hex(h256.data(), h256.size()));
    LOG_INFO("Demo", "Стрибог-512: " + utils::to_hex(h512.data(), h512.size()).substr(0, 32) + "...");

    // 2. Потоковый Стрибог
    Streebog256Context ctx;
    ctx.update(reinterpret_cast<const uint8_t*>(msg), strlen(msg) / 2);
    ctx.update(reinterpret_cast<const uint8_t*>(msg) + strlen(msg) / 2,
               strlen(msg) - strlen(msg) / 2);
    auto h256_stream = ctx.finalize();
    LOG_INFO("Demo", "Стрибог-256 потоковый==one-shot: " +
             std::string(h256_stream == h256 ? "OK" : "ОШИБКА"));

    // 3. Кузнечик ECB + CTR (ГОСТ Р 34.12-2015)
    auto key32 = utils::secure_random(32);
    Grasshopper gh(key32.data(), key32.size());

    GBlock blk{};
    blk.fill(0x42);
    auto enc_blk = gh.encrypt_block(blk);
    auto dec_blk = gh.decrypt_block(enc_blk);
    LOG_INFO("Demo", "Кузнечик ECB: " + std::string(dec_blk == blk ? "OK" : "ОШИБКА"));

    std::vector<uint8_t> data(64, 0xAB);
    std::array<uint8_t, 8> iv8{};
    auto r = utils::secure_random(8);
    std::copy(r.begin(), r.end(), iv8.begin());
    auto enc_ctr = gh.encrypt_ctr(data, iv8);
    auto dec_ctr = gh.decrypt_ctr(enc_ctr, iv8);
    LOG_INFO("Demo", "Кузнечик CTR: " + std::string(dec_ctr == data ? "OK" : "ОШИБКА"));

    // 4. MAC Кузнечика (имитовставка)
    auto mac_val = gh.mac(data);
    LOG_INFO("Demo", "Кузнечик MAC (8 байт): " + utils::to_hex(mac_val.data(), mac_val.size()));

    // 5. HMAC-Стрибог-256/512
    auto hmac_key = utils::secure_random(32);
    auto hmac256 = hmac_streebog256(hmac_key, data);
    auto hmac512 = hmac_streebog512(hmac_key, data);
    LOG_INFO("Demo", "HMAC-Стрибог-256: " + utils::to_hex(hmac256.data(), hmac256.size()));
    LOG_INFO("Demo", "HMAC-Стрибог-512: " + utils::to_hex(hmac512.data(), hmac512.size()).substr(0, 32) + "...");

    // 6. ГОСТ Р 34.10-2012 ЭЦП
    try {
        auto kp = GostKeyPair::generate(GostCurve::TC26_GOST_3410_12_256_A);
        LOG_INFO("Demo", "ГОСТ-ключ: " + std::to_string(kp.public_key_der().size()) + " байт (pub)");

        GostSigner signer(kp);
        auto sig = signer.sign(h256.data(), h256.size());

        GostVerifier verifier(kp.public_key_der(), GostCurve::TC26_GOST_3410_12_256_A);
        bool ok = verifier.verify(h256.data(), h256.size(), sig);
        LOG_INFO("Demo", "Подпись ГОСТ Р 34.10-2012: " + std::string(ok ? "OK" : "ОШИБКА") +
                 " (" + std::to_string(sig.size()) + " байт)");

        // Проверяем обнаружение подмены
        auto h_bad = h256; h_bad[0] ^= 0xFF;
        bool tampered = verifier.verify(h_bad.data(), h_bad.size(), sig);
        LOG_INFO("Demo", "Защита от подмены данных: " + std::string(!tampered ? "OK" : "ОШИБКА"));
    } catch (const std::exception& e) {
        LOG_WARN("Demo", std::string("ГОСТ 34.10: ") + e.what());
    }

    // 7. KDF: вывод ключей из пароля (ГОСТ Р 34.11-2012)
    auto salt = utils::secure_random(32);
    auto dk = kdf_from_password("gost-demo-password", salt, 1000, 32);
    LOG_INFO("Demo", "KDF из пароля: " + utils::to_hex(dk).substr(0, 32) + "...");

    // 8. HKDF-Стрибог-256
    std::vector<uint8_t> info = {'c','l','t'};
    auto hk = hkdf_streebog256(key32, salt, info, 64);
    LOG_INFO("Demo", "HKDF-Стрибог-256 (64 байта): " + utils::to_hex(hk).substr(0, 32) + "...");

    // 9. Зашифрованное хранилище (Кузнечик-CTR + HMAC-Стрибог-256)
    std::string secret = "Конфиденциальный документ ГОСТ";
    std::vector<uint8_t> plain(secret.begin(), secret.end());
    auto blob = storage::EncryptedStorage::encrypt(plain, key32);
    auto recovered = storage::EncryptedStorage::decrypt(blob, key32);
    LOG_INFO("Demo", "EncryptedStorage: " + std::string(recovered == plain ? "OK" : "ОШИБКА") +
             " (plain=" + std::to_string(plain.size()) +
             " blob=" + std::to_string(blob.size()) + " байт)");

    // 10. Подписание документа (CAdES-BES)
    try {
        auto kp = GostKeyPair::generate(GostCurve::TC26_GOST_3410_12_256_A);
        document::DocumentSigner signer(kp.private_key_der(), {});
        auto signed_doc = signer.sign(plain);
        LOG_INFO("Demo", "CAdES-BES подпись: " +
                 std::to_string(signed_doc.cms_data.size()) + " байт");
    } catch (const std::exception& e) {
        LOG_WARN("Demo", std::string("CAdES: ") + e.what());
    }

    LOG_AUDIT("DEMO_COMPLETE", "client", "system", "demo_run", true, "все алгоритмы проверены");
    LOG_INFO("Demo", "=== Демонстрация завершена успешно ===");
}

// ── TLS-режим ──────────────────────────────────────────────────────────────────

static void run_tls(const ClientConfig& cfg) {
    network::TlsClient::Config tls_cfg;
    tls_cfg.cert_file    = cfg.cert_file;
    tls_cfg.key_file     = cfg.key_file;
    tls_cfg.ca_cert_file = cfg.ca_cert_file;
    tls_cfg.verify_server = true;
    tls_cfg.prefer_gost_ciphers = true;
    tls_cfg.timeout_sec = 30;

    network::TlsClient tls(tls_cfg);
    LOG_INFO("Client", "Подключение: " + cfg.host + ":" + std::to_string(cfg.port));

    if (!tls.connect(cfg.host, cfg.port)) {
        LOG_ERROR("Client", "Не удалось подключиться");
        return;
    }
    LOG_INFO("Client", "TLS: " + tls.tls_version() + "/" + tls.negotiated_cipher());

    // HELLO
    network::Message msg, resp;
    msg.type = network::MessageType::HELLO; msg.seq_no = 1;
    std::string hello = "GOST-CLIENT/1.0";
    msg.payload.assign(hello.begin(), hello.end());
    if (!network::send_message(tls.fd(), msg, {})) { tls.disconnect(); return; }
    auto r = network::recv_message(tls.fd(), {});
    if (r) LOG_INFO("Client", "Сервер: " + std::string(r->payload.begin(), r->payload.end()));

    // AUTH_REQUEST → challenge
    msg.type = network::MessageType::AUTH_REQUEST; msg.seq_no = 2; msg.payload.clear();
    if (!network::send_message(tls.fd(), msg, {})) { tls.disconnect(); return; }
    r = network::recv_message(tls.fd(), {});
    if (!r || r->type != network::MessageType::AUTH_CHALLENGE) {
        LOG_ERROR("Client", "Ожидался AUTH_CHALLENGE");
        tls.disconnect(); return;
    }

    // HASH_REQUEST — пример использования
    msg.type = network::MessageType::HASH_REQUEST; msg.seq_no = 3;
    std::string data_str = "ГОСТ Р 34.11-2012 хэш запрос";
    msg.payload.assign(data_str.begin(), data_str.end());
    if (!network::send_message(tls.fd(), msg, {})) { tls.disconnect(); return; }
    r = network::recv_message(tls.fd(), {});
    if (r && r->type == network::MessageType::HASH_RESPONSE)
        LOG_INFO("Client", "Серверный хэш Стрибог-256: " + utils::to_hex(r->payload));

    tls.disconnect();
    LOG_INFO("Client", "Сеанс завершён");
}

// ── main ──────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    ClientConfig cfg;
    for (int i = 1; i < argc; ++i) {
        if      (!strcmp(argv[i], "--demo"))              cfg.demo_mode = true;
        else if (i + 1 < argc) {
            if      (!strcmp(argv[i], "--host"))  cfg.host = argv[++i];
            else if (!strcmp(argv[i], "--port"))  cfg.port = (uint16_t)std::stoi(argv[++i]);
            else if (!strcmp(argv[i], "--cert"))  cfg.cert_file = argv[++i];
            else if (!strcmp(argv[i], "--key"))   cfg.key_file  = argv[++i];
            else if (!strcmp(argv[i], "--ca"))    cfg.ca_cert_file = argv[++i];
            else if (!strcmp(argv[i], "--sign"))  cfg.sign_file = argv[++i];
        }
    }

    common::Logger::instance().set_level(common::LogLevel::INFO);
    LOG_INFO("Client", "ГОСТ клиент документооборота v1.0");

    bool has_certs = utils::file_exists(cfg.cert_file) && utils::file_exists(cfg.key_file);

    if (cfg.demo_mode || !has_certs) {
        run_demo();
    } else {
        run_tls(cfg);
    }
    return 0;
}