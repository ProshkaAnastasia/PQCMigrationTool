#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// Хранилище ключей (аналог HSM в программном исполнении)
// Ключи зашифрованы Кузнечиком, защищены HMAC-Стрибог-256
// ─────────────────────────────────────────────────────────────────────────────
#include <string>
#include <vector>
#include <optional>
#include <ctime>

namespace gost { namespace storage {

struct KeyEntry {
    std::string id;              // Идентификатор ключа
    std::string type;            // "gost-3410-2012-256", "grasshopper", "magma"
    std::string algorithm;       // Назначение
    std::time_t created;
    std::time_t expires;
    bool active;
    std::vector<uint8_t> encrypted_key_material;  // Зашифрован мастер-ключом
};

class KeyVault {
public:
    explicit KeyVault(const std::string& vault_file,
                      const std::string& master_password);
    ~KeyVault();

    // Инициализация нового хранилища
    static void create(const std::string& vault_file,
                       const std::string& master_password);

    // Сохранение ключа
    std::string store_key(const std::string& id,
                          const std::string& type,
                          const std::vector<uint8_t>& key_material,
                          int validity_days = 365);

    // Извлечение ключа
    std::optional<std::vector<uint8_t>> load_key(const std::string& id);

    // Генерация и сохранение новой пары ключей ГОСТ Р 34.10-2012
    std::string generate_gost_keypair(const std::string& id,
                                      const std::string& curve = "tc26-A");

    // Список ключей
    std::vector<KeyEntry> list_keys() const;

    // Удаление ключа
    bool revoke_key(const std::string& id);

    // Экспорт публичного ключа (закрытый остаётся в хранилище)
    std::vector<uint8_t> export_public_key(const std::string& id);

    // Верификация целостности хранилища (HMAC-Стрибог-256)
    bool verify_integrity() const;

    // Смена мастер-пароля с перешифрованием хранилища
    void change_password(const std::string& old_password,
                         const std::string& new_password);

private:
    struct Impl;
    Impl* impl_;
};

}} // namespace gost::storage