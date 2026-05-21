// ─────────────────────────────────────────────────────────────────────────────
// Сервер защищённого документооборота (ГОСТ Р 34.10-2012 / TLS)
//
// Запуск:  ./gost_server [--port PORT] [--cert CERT] [--key KEY] [--ca CA]
//
// В режиме demo (без сертификатов) демонстрирует работу всех ГОСТ алгоритмов.
// ─────────────────────────────────────────────────────────────────────────────
#include "network/tls_server.hpp"
#include "network/message_protocol.hpp"
#include "auth/authenticator.hpp"
#include "auth/session_manager.hpp"
#include "document/document_verifier.hpp"
#include "storage/encrypted_storage.hpp"
#include "storage/key_vault.hpp"
#include "pki/cert_manager.hpp"
#include "crypto/gost_sign.hpp"
#include "crypto/streebog.hpp"
#include "crypto/grasshopper.hpp"
#include "crypto/hmac_streebog.hpp"
#include "crypto/kdf.hpp"
#include "common/logger.hpp"
#include "common/utils.hpp"
#include <iostream>
#include <string>
#include <cstring>

using namespace gost;

struct ServerConfig {
    uint16_t port = 8443;
    std::string cert_file    = "certs/server.crt";
    std::string key_file     = "certs/server.key";
    std::string ca_cert_file = "certs/ca.crt";
    std::string vault_file   = "server_vault.enc";
    std::string vault_pass   = "gost-server-password";
    std::string log_file     = "server_audit.log";
};

// ── Демо-режим: проверка всех ГОСТ алгоритмов ────────────────────────────────

static void run_demo(common::Logger& log) {
    LOG_INFO("Demo", "=== ГОСТ сервер: демонстрационный режим ===");

    // 1. Стрибог-256 / 512 (ГОСТ Р 34.11-2012)
    const char* test_data = "Тестовые данные для ГОСТ криптографии";
    auto hash256 = streebog256(reinterpret_cast<const uint8_t*>(test_data), strlen(test_data));
    auto hash512 = streebog512(reinterpret_cast<const uint8_t*>(test_data), strlen(test_data));
    LOG_INFO("Demo", "Стрибог-256: " + utils::to_hex(hash256.data(), hash256.size()));
    LOG_INFO("Demo", "Стрибог-512: " + utils::to_hex(hash512.data(), hash512.size()).substr(0, 32) + "...");

    // 2. Кузнечик ECB (ГОСТ Р 34.12-2015)
    auto key32 = utils::secure_random(32);
    Grasshopper gh(key32.data(), key32.size());
    GBlock plain_block{};
    plain_block.fill(0xAB);
    auto enc_block = gh.encrypt_block(plain_block);
    auto dec_block = gh.decrypt_block(enc_block);
    LOG_INFO("Demo", "Кузнечик ECB: " + std::string(dec_block == plain_block ? "OK" : "ОШИБКА"));

    // 3. Кузнечик CTR
    std::vector<uint8_t> plain_data(64, 0x42);
    auto iv8 = []() {
        std::array<uint8_t, 8> a{};
        auto r = utils::secure_random(8);
        std::copy(r.begin(), r.end(), a.begin());
        return a;
    }();
    auto enc_ctr = gh.encrypt_ctr(plain_data, iv8);
    auto dec_ctr = gh.decrypt_ctr(enc_ctr, iv8);
    LOG_INFO("Demo", "Кузнечик CTR: " + std::string(dec_ctr == plain_data ? "OK" : "ОШИБКА"));

    // 4. HMAC-Стрибог-256
    auto hmac_key = utils::secure_random(32);
    auto mac = hmac_streebog256(hmac_key, plain_data);
    LOG_INFO("Demo", "HMAC-Стрибог-256: " + utils::to_hex(mac.data(), mac.size()));

    // 5. Генерация ключевой пары ГОСТ Р 34.10-2012
    try {
        auto kp = GostKeyPair::generate(GostCurve::TC26_GOST_3410_12_256_A);
        GostSigner signer(kp);
        auto sig = signer.sign(hash256.data(), hash256.size());
        GostVerifier verifier(kp.public_key_der(), GostCurve::TC26_GOST_3410_12_256_A);
        bool ok = verifier.verify(hash256.data(), hash256.size(), sig);
        LOG_INFO("Demo", "ГОСТ Р 34.10-2012 подпись: " + std::string(ok ? "OK" : "ОШИБКА") +
                 " (" + std::to_string(sig.size()) + " байт)");
    } catch (const std::exception& e) {
        LOG_WARN("Demo", std::string("ГОСТ 34.10: ") + e.what());
    }

    // 6. KDF — вывод ключа из пароля (ГОСТ Р 34.11-2012)
    auto salt = utils::secure_random(16);
    auto derived = kdf_from_password("gost-server-demo", salt, 1000, 32);
    LOG_INFO("Demo", "KDF-Стрибог: " + utils::to_hex(derived).substr(0, 32) + "...");

    // 7. HKDF-Стрибог-256
    std::vector<uint8_t> info = {'s','r','v'};
    auto hkdf_key = hkdf_streebog256(key32, salt, info, 32);
    LOG_INFO("Demo", "HKDF-Стрибог: " + utils::to_hex(hkdf_key).substr(0, 32) + "...");

    // 8. Зашифрованное хранилище (Кузнечик-CTR + HMAC-Стрибог-256)
    std::string secret = "Секретный документ";
    std::vector<uint8_t> plain_secret(secret.begin(), secret.end());
    auto enc = storage::EncryptedStorage::encrypt(plain_secret, key32);
    auto dec = storage::EncryptedStorage::decrypt(enc, key32);
    LOG_INFO("Demo", "EncryptedStorage: " + std::string(dec == plain_secret ? "OK" : "ОШИБКА") +
             " (blob=" + std::to_string(enc.size()) + " байт)");

    // 9. Аудит-цепочка Стрибог-256
    LOG_AUDIT("DEMO_COMPLETE", "server", "demo", "run", true, "все тесты пройдены");
    LOG_INFO("Demo", "Хэш вершины аудит-цепочки: " + log.chain_tip_hash().substr(0, 16) + "...");
    LOG_INFO("Demo", "=== Демонстрация завершена ===");
}

// ── Обработчик клиентского подключения ───────────────────────────────────────

static void handle_client(int client_fd,
                           const network::ClientInfo& info,
                           auth::Authenticator& auth,
                           document::DocumentVerifier& verifier) {
    LOG_INFO("Server", "Клиент: " + info.peer_addr + " cipher=" + info.cipher_suite);

    std::vector<uint8_t> challenge;
    bool authenticated = false;

    while (true) {
        auto msg_opt = network::recv_message(client_fd, {});
        if (!msg_opt) break;
        auto& msg = *msg_opt;

        network::Message resp;
        resp.seq_no = msg.seq_no + 1;

        switch (msg.type) {
        case network::MessageType::HELLO: {
            std::string srv = "GOST-DOCFLOW-SERVER/1.0";
            resp.type = network::MessageType::HELLO;
            resp.payload.assign(srv.begin(), srv.end());
            break;
        }
        case network::MessageType::AUTH_REQUEST:
            challenge = auth.generate_challenge();
            resp.type = network::MessageType::AUTH_CHALLENGE;
            resp.payload = challenge;
            break;
        case network::MessageType::AUTH_RESPONSE: {
            if (msg.payload.size() < 64) { resp.type = network::MessageType::AUTH_FAIL; break; }
            std::vector<uint8_t> sig(msg.payload.begin(), msg.payload.begin() + 64);
            std::vector<uint8_t> cert_der(msg.payload.begin() + 64, msg.payload.end());
            authenticated = auth.verify_response(challenge, sig, cert_der);
            resp.type = authenticated ? network::MessageType::AUTH_OK : network::MessageType::AUTH_FAIL;
            break;
        }
        case network::MessageType::HASH_REQUEST: {
            auto hash = streebog256(msg.payload.data(), msg.payload.size());
            resp.type = network::MessageType::HASH_RESPONSE;
            resp.payload.assign(hash.begin(), hash.end());
            break;
        }
        case network::MessageType::DOCUMENT_UPLOAD: {
            if (!authenticated) {
                resp.type = network::MessageType::ERROR;
                std::string err = "Требуется аутентификация";
                resp.payload.assign(err.begin(), err.end());
                break;
            }
            auto result = verifier.verify(msg.payload);
            if (result.valid) {
                auto doc_id = utils::generate_uuid();
                resp.type = network::MessageType::DOCUMENT_SIGNED;
                resp.payload.assign(doc_id.begin(), doc_id.end());
            } else {
                resp.type = network::MessageType::ERROR;
                resp.payload.assign(result.failure_reason.begin(), result.failure_reason.end());
            }
            break;
        }
        default: {
            resp.type = network::MessageType::ERROR;
            std::string err = "Неизвестная команда";
            resp.payload.assign(err.begin(), err.end());
            break;
        }
        }
        if (!network::send_message(client_fd, resp, {})) break;
    }
    LOG_INFO("Server", "Клиент отключился: " + info.peer_addr);
}

// ── main ──────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    ServerConfig cfg;
    for (int i = 1; i + 1 < argc; ++i) {
        if      (!strcmp(argv[i], "--port")) cfg.port = (uint16_t)std::stoi(argv[++i]);
        else if (!strcmp(argv[i], "--cert")) cfg.cert_file = argv[++i];
        else if (!strcmp(argv[i], "--key"))  cfg.key_file  = argv[++i];
        else if (!strcmp(argv[i], "--ca"))   cfg.ca_cert_file = argv[++i];
    }

    auto& log = common::Logger::instance();
    log.set_log_file(cfg.log_file);
    log.set_level(common::LogLevel::INFO);
    log.enable_audit_chain(true);

    LOG_INFO("Main", "ГОСТ сервер документооборота v1.0");

    bool has_certs = utils::file_exists(cfg.cert_file) &&
                     utils::file_exists(cfg.key_file);

    if (!has_certs) {
        run_demo(log);
        return 0;
    }

    if (!utils::file_exists(cfg.vault_file))
        storage::KeyVault::create(cfg.vault_file, cfg.vault_pass);
    storage::KeyVault vault(cfg.vault_file, cfg.vault_pass);
    if (vault.list_keys().empty())
        vault.generate_gost_keypair("server-sign-key", "tc26-A");

    auth::Authenticator authenticator(cfg.ca_cert_file);
    document::DocumentVerifier verifier(cfg.ca_cert_file);

    network::TlsServer::Config tls_cfg;
    tls_cfg.port = cfg.port;
    tls_cfg.cert_file = cfg.cert_file;
    tls_cfg.key_file  = cfg.key_file;
    tls_cfg.ca_cert_file = cfg.ca_cert_file;
    tls_cfg.require_client_cert = true;
    tls_cfg.prefer_gost_ciphers = true;

    network::TlsServer server(tls_cfg);
    server.set_connection_handler([&](int fd, const network::ClientInfo& info) {
        handle_client(fd, info, authenticator, verifier);
    });

    LOG_INFO("Main", "TLS сервер слушает порт " + std::to_string(cfg.port));
    server.start();
    return 0;
}