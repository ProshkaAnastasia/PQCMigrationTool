// ─────────────────────────────────────────────────────────────────────────────
// Хранилище ключей (программный аналог HSM)
//
// Ключи хранятся в JSON-файле, зашифрованном через EncryptedStorage
// (Кузнечик-CTR + HMAC-Стрибог-256).
// Мастер-ключ выводится из пароля через kdf_from_password (ГОСТ Р 34.11-2012).
// ─────────────────────────────────────────────────────────────────────────────
#include "storage/key_vault.hpp"
#include "storage/encrypted_storage.hpp"
#include "crypto/gost_sign.hpp"
#include "crypto/kdf.hpp"
#include "common/logger.hpp"
#include "common/utils.hpp"
#include <vector>
#include <unordered_map>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <cstring>

namespace gost { namespace storage {

static std::string entry_to_json(const KeyEntry& e) {
    std::ostringstream ss;
    ss << "{\"id\":\"" << e.id
       << "\",\"type\":\"" << e.type
       << "\",\"algorithm\":\"" << e.algorithm
       << "\",\"created\":" << e.created
       << ",\"expires\":" << e.expires
       << ",\"active\":" << (e.active ? "true" : "false")
       << ",\"key\":\"" << utils::to_base64(e.encrypted_key_material)
       << "\"}";
    return ss.str();
}

static std::string vault_to_json(const std::vector<KeyEntry>& entries) {
    std::string s = "[";
    for (size_t i = 0; i < entries.size(); ++i) {
        if (i) s += ",";
        s += entry_to_json(entries[i]);
    }
    s += "]";
    return s;
}

static std::string json_str(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\":\"";
    auto pos = json.find(search);
    if (pos == std::string::npos) return {};
    pos += search.size();
    auto end = json.find('"', pos);
    return json.substr(pos, end - pos);
}
static long long json_num(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\":";
    auto pos = json.find(search);
    if (pos == std::string::npos) return 0;
    pos += search.size();
    auto end = json.find_first_of(",}", pos);
    try { return std::stoll(json.substr(pos, end - pos)); } catch (...) { return 0; }
}
static bool json_bool(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\":";
    auto pos = json.find(search);
    if (pos == std::string::npos) return false;
    pos += search.size();
    return json.substr(pos, 4) == "true";
}

static std::vector<KeyEntry> json_to_vault(const std::string& json) {
    std::vector<KeyEntry> entries;
    size_t pos = 0;
    while ((pos = json.find('{', pos)) != std::string::npos) {
        int depth = 0;
        size_t end = pos;
        while (end < json.size()) {
            if (json[end] == '{') ++depth;
            else if (json[end] == '}') { --depth; if (depth == 0) break; }
            ++end;
        }
        std::string obj = json.substr(pos, end - pos + 1);
        KeyEntry e;
        e.id = json_str(obj, "id");
        e.type = json_str(obj, "type");
        e.algorithm = json_str(obj, "algorithm");
        e.created = (std::time_t)json_num(obj, "created");
        e.expires = (std::time_t)json_num(obj, "expires");
        e.active = json_bool(obj, "active");
        e.encrypted_key_material = utils::from_base64(json_str(obj, "key"));
        if (!e.id.empty()) entries.push_back(std::move(e));
        pos = end + 1;
    }
    return entries;
}

struct KeyVault::Impl {
    std::string vault_file;
    std::vector<uint8_t> master_key;
    std::vector<KeyEntry> entries;
    mutable std::mutex mu;

    void load() {
        if (!utils::file_exists(vault_file)) return;
        auto blob = utils::read_file(vault_file);
        auto plaintext = EncryptedStorage::decrypt(blob, master_key);
        std::string json(plaintext.begin(), plaintext.end());
        entries = json_to_vault(json);
    }

    void save() {
        std::string json = vault_to_json(entries);
        std::vector<uint8_t> plaintext(json.begin(), json.end());
        auto blob = EncryptedStorage::encrypt(plaintext, master_key);
        utils::write_file(vault_file, blob);
    }

    std::vector<uint8_t> wrap_key(const std::vector<uint8_t>& key_material) {
        return EncryptedStorage::encrypt(key_material, master_key);
    }

    std::vector<uint8_t> unwrap_key(const std::vector<uint8_t>& wrapped) {
        return EncryptedStorage::decrypt(wrapped, master_key);
    }
};

// Фиксированная соль хранилища
static const uint8_t VAULT_SALT[32] = {
    0x47,0x4F,0x53,0x54,0x56,0x61,0x75,0x6C,
    0x74,0x53,0x61,0x6C,0x74,0x32,0x30,0x31,
    0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};

// kdf_from_password принимает std::string и std::vector<uint8_t> соль
static std::vector<uint8_t> derive_master_key(const std::string& password) {
    std::vector<uint8_t> salt(VAULT_SALT, VAULT_SALT + sizeof(VAULT_SALT));
    return kdf_from_password(password, salt, 100000, 32);
}

KeyVault::KeyVault(const std::string& vault_file, const std::string& password)
    : impl_(new Impl()) {
    impl_->vault_file = vault_file;
    impl_->master_key = derive_master_key(password);
    impl_->load();
    LOG_INFO("KeyVault", "Открыто хранилище: " + vault_file +
             " (" + std::to_string(impl_->entries.size()) + " ключей)");
}

KeyVault::~KeyVault() { delete impl_; }

void KeyVault::create(const std::string& vault_file, const std::string& password) {
    auto master_key = derive_master_key(password);
    std::vector<uint8_t> empty_json = {'[', ']'};
    auto blob = EncryptedStorage::encrypt(empty_json, master_key);
    utils::write_file(vault_file, blob);
    LOG_INFO("KeyVault", "Создано новое хранилище: " + vault_file);
}

std::string KeyVault::store_key(const std::string& id,
                                 const std::string& type,
                                 const std::vector<uint8_t>& key_material,
                                 int validity_days) {
    std::lock_guard<std::mutex> lock(impl_->mu);
    KeyEntry e;
    e.id = id.empty() ? utils::generate_uuid() : id;
    e.type = type;
    e.algorithm = type;
    e.created = std::time(nullptr);
    e.expires = e.created + (std::time_t)validity_days * 86400;
    e.active = true;
    e.encrypted_key_material = impl_->wrap_key(key_material);
    impl_->entries.push_back(e);
    impl_->save();
    LOG_AUDIT("KEY_STORE", "vault", e.id, "store", true, "type=" + type);
    return e.id;
}

std::optional<std::vector<uint8_t>> KeyVault::load_key(const std::string& id) {
    std::lock_guard<std::mutex> lock(impl_->mu);
    for (const auto& e : impl_->entries) {
        if (e.id == id) {
            if (!e.active) { LOG_WARN("KeyVault", "Ключ деактивирован: " + id); return std::nullopt; }
            if (e.expires < std::time(nullptr)) { LOG_WARN("KeyVault", "Ключ просрочен: " + id); return std::nullopt; }
            LOG_AUDIT("KEY_LOAD", "vault", id, "load", true);
            return impl_->unwrap_key(e.encrypted_key_material);
        }
    }
    return std::nullopt;
}

std::string KeyVault::generate_gost_keypair(const std::string& id,
                                             const std::string& curve) {
    GostCurve c = GostCurve::TC26_GOST_3410_12_256_A;
    if (curve == "tc26-512a") c = GostCurve::TC26_GOST_3410_12_512_A;
    else if (curve == "tc26-512b") c = GostCurve::TC26_GOST_3410_12_512_B;
    auto kp = GostKeyPair::generate(c);
    auto priv_der = kp.private_key_der();
    std::string key_id = store_key(id, "gost-3410-2012-256", priv_der, 365);
    LOG_AUDIT("KEY_GENERATE", "vault", key_id, "generate", true, "curve=" + curve);
    return key_id;
}

std::vector<KeyEntry> KeyVault::list_keys() const {
    std::lock_guard<std::mutex> lock(impl_->mu);
    return impl_->entries;
}

bool KeyVault::revoke_key(const std::string& id) {
    std::lock_guard<std::mutex> lock(impl_->mu);
    for (auto& e : impl_->entries) {
        if (e.id == id) {
            e.active = false;
            impl_->save();
            LOG_AUDIT("KEY_REVOKE", "vault", id, "revoke", true);
            return true;
        }
    }
    return false;
}

std::vector<uint8_t> KeyVault::export_public_key(const std::string& id) {
    auto priv_der = load_key(id);
    if (!priv_der) throw std::runtime_error("Ключ не найден: " + id);
    auto kp = GostKeyPair::from_private_der(*priv_der, GostCurve::TC26_GOST_3410_12_256_A);
    LOG_AUDIT("KEY_EXPORT_PUB", "vault", id, "export_pub", true);
    return kp.public_key_der();
}

bool KeyVault::verify_integrity() const {
    return EncryptedStorage::verify_integrity(impl_->vault_file, impl_->master_key);
}

void KeyVault::change_password(const std::string& old_pass, const std::string& new_pass) {
    std::lock_guard<std::mutex> lock(impl_->mu);
    auto old_key = derive_master_key(old_pass);
    if (old_key != impl_->master_key)
        throw std::runtime_error("KeyVault: неверный текущий пароль");
    auto new_master = derive_master_key(new_pass);
    for (auto& e : impl_->entries) {
        auto raw = impl_->unwrap_key(e.encrypted_key_material);
        impl_->master_key = new_master;
        e.encrypted_key_material = impl_->wrap_key(raw);
        utils::secure_zero(raw);
    }
    impl_->master_key = new_master;
    impl_->save();
    LOG_AUDIT("VAULT_REKEY", "vault", impl_->vault_file, "change_password", true);
}

}} // namespace gost::storage