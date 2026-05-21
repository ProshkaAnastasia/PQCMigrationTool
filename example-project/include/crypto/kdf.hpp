#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// Производство ключей (Key Derivation Functions) по ГОСТ
//
// Стандарты:
//   Р 50.1.113-2016    — Использование HMAC-Стрибог для KDF
//   Р 1323565.1.022-2018 — Методы создания производных ключей
//   ГОСТ Р 34.12-2015   — КДФ на основе шифра Кузнечик (ACPKM)
//   RFC 7836            — TLS KDF на основе ГОСТ
//
// Протокол VKO ГОСТ Р 34.10-2012:
//   Функция согласования ключей на основе ЭК Диффи-Хеллман
//   VKO = КДФ(d_A · Q_B, UKM)
//   где UKM — уникальный ключевой материал (nonce)
//
// Метод ACPKM (Р 1323565.1.017-2018):
//   Автоматическая смена производных ключей при шифровании
//   большого объёма данных в режиме счётчика Кузнечиком
// ─────────────────────────────────────────────────────────────────────────────
#include <cstdint>
#include <vector>
#include <string>
#include <array>

namespace gost {

// Производный ключ ГОСТ — из пароля (аналог PBKDF2 для ГОСТ)
std::vector<uint8_t> kdf_from_password(
    const std::string& password,
    const std::vector<uint8_t>& salt,
    uint32_t iterations = 10000,
    size_t key_len = 32
);

// VKO — Выработка конфиденциального ключа (ГОСТ Р 34.10-2012)
// Протокол Диффи-Хеллман на эллиптических кривых
std::vector<uint8_t> vko_gost_r3410_2012(
    const std::vector<uint8_t>& private_key_der,  // Закрытый ключ стороны A
    const std::vector<uint8_t>& public_key_der,   // Открытый ключ стороны B
    const std::array<uint8_t, 8>& ukm             // Уникальный ключевой материал
);

// KDF согласно Р 50.1.113-2016 (выработка производных ключей)
// Используется для разделения мастер-ключа на сессионные ключи
std::vector<uint8_t> kdf_tree_gostr3411_2012_256(
    const std::vector<uint8_t>& k_root,   // Корневой ключ
    const std::string& label,             // Метка (назначение ключа)
    const std::vector<uint8_t>& seed,     // Начальное значение
    size_t r = 1                          // Счётчик
);

// ACPKM — Автоматическая смена ключа (Р 1323565.1.017-2018)
// Применяется при длительном шифровании большого объёма данных
class AcpkmKeySchedule {
public:
    AcpkmKeySchedule(const std::vector<uint8_t>& initial_key,
                     size_t section_size = 4096);  // Размер секции в байтах

    // Возвращает текущий ключ и при необходимости производит смену
    std::vector<uint8_t> get_key_for_position(uint64_t byte_position);

private:
    std::vector<uint8_t> current_key_;
    size_t section_size_;
    uint64_t current_section_;

    std::vector<uint8_t> derive_next_key(const std::vector<uint8_t>& key);
};

// Разворачивание ключа Кузнечик для хранения (key wrap)
// Аналог RFC 3394 (AES Key Wrap), но с Кузнечиком
std::vector<uint8_t> key_wrap_grasshopper(
    const std::vector<uint8_t>& key_to_wrap,
    const std::vector<uint8_t>& wrapping_key
);
std::vector<uint8_t> key_unwrap_grasshopper(
    const std::vector<uint8_t>& wrapped_key,
    const std::vector<uint8_t>& wrapping_key
);

} // namespace gost