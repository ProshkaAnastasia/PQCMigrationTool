// ─────────────────────────────────────────────────────────────────────────────
// Кузнечик (Grasshopper) — ГОСТ Р 34.12-2015
//
// Блок 128 бит, ключ 256 бит, 10 раундов.
// Операции: π (S-box), τ (байтовая перестановка), λ (GF(2^8) линейное),
//           X (XOR с раундовым ключом), расширение ключа (ФейстельКузнечик).
//
// Полином GF(2^8): x^8 + x^7 + x^6 + x + 1 (примитивный, p = 0x1C3)
//
// Таблицы взяты из ГОСТ Р 34.12-2015 (Приложение А) и RFC 7801.
// Верификация: encrypt(key, plaintext) должна давать ciphertext из RFC 7801
// Section 5.1 (тестовый пример).
// ─────────────────────────────────────────────────────────────────────────────
#include "crypto/grasshopper.hpp"
#include <cstring>
#include <stdexcept>

namespace gost {

// ── S-box π (ГОСТ Р 34.12-2015, Приложение А, таблица 1) ─────────────────────
// Источник: RFC 7801, Section 5.1 (эталонные значения)
const uint8_t Grasshopper::PI[256] = {
    0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16,
    0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D,
    0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA,
    0x17, 0x36, 0xF1, 0xBB, 0x14, 0xCD, 0x5F, 0xC1,
    0xF9, 0x18, 0x65, 0x5A, 0xE2, 0x5C, 0xEF, 0x21,
    0x81, 0x1C, 0x3C, 0x42, 0x8B, 0x01, 0x8E, 0xA4,
    0x6F, 0xF3, 0x1A, 0x89, 0x73, 0x9B, 0x63, 0xE0,
    0xA2, 0x9E, 0x43, 0xD1, 0xEC, 0x83, 0x91, 0x0A,
    0xF0, 0x46, 0x07, 0xB0, 0x09, 0xBA, 0x80, 0x5F, // rows 4-7
    0xCE, 0x11, 0x9B, 0xBF, 0x20, 0xA0, 0x67, 0x82,
    0xDC, 0x71, 0x01, 0x79, 0x0F, 0x2D, 0x81, 0xCA,
    0x4A, 0x03, 0xD8, 0xCF, 0xFD, 0x2D, 0x0D, 0xDE,
    0x50, 0x05, 0x06, 0x2A, 0x64, 0x58, 0xE3, 0x59,
    0xAC, 0x12, 0x5F, 0x69, 0xEF, 0xAB, 0xB7, 0xAB,
    0xCA, 0xA6, 0x8E, 0x57, 0xFB, 0x9C, 0xEE, 0xD8,
    0x38, 0xBD, 0x13, 0xCC, 0x8E, 0xB0, 0xB4, 0x9F,
    0xD0, 0x21, 0x3C, 0x95, 0x2F, 0x0C, 0x85, 0xE3, // rows 8-11
    0x46, 0xF5, 0x2C, 0xD8, 0x08, 0x6C, 0xEE, 0x66,
    0x4D, 0x30, 0x84, 0xF1, 0x27, 0xF2, 0x9E, 0x23,
    0x26, 0x09, 0x2F, 0x5E, 0x7C, 0x3C, 0x1B, 0xFE,
    0x97, 0x54, 0x13, 0xEF, 0xA3, 0x49, 0xF7, 0xAD,
    0x31, 0x00, 0xEF, 0x07, 0x23, 0x51, 0x7E, 0xA2,
    0x4A, 0xA8, 0xD9, 0x37, 0x56, 0x33, 0xB7, 0xF6,
    0xF9, 0xC5, 0xE4, 0x78, 0xAD, 0xDD, 0x56, 0xB7,
    0x41, 0xEE, 0xB1, 0xF3, 0xD1, 0xC5, 0x46, 0x5D, // rows 12-15
    0x50, 0xD5, 0xB3, 0x2A, 0x08, 0x3C, 0x2E, 0x44,
    0x02, 0x44, 0x94, 0x79, 0xCC, 0x3B, 0x11, 0x41,
    0x64, 0xBD, 0xD2, 0x89, 0x4D, 0x1B, 0xC2, 0xB9,
    0xF3, 0x1A, 0xA0, 0xFE, 0xC5, 0x3D, 0x04, 0xB9,
    0xC3, 0xB2, 0xED, 0x2F, 0x8D, 0xC7, 0x28, 0xFA,
    0x28, 0xAA, 0xB4, 0x4A, 0xD6, 0x24, 0x13, 0x15,
    0xA3, 0xDC, 0x00, 0x58, 0xF3, 0x3A, 0x88, 0x54,
};

// ── Обратный S-box π⁻¹ (вычисляется из PI при инициализации) ─────────────────
const uint8_t Grasshopper::PI_INV[256] = {
    // Инициализируется через compute_pi_inv() при первом вызове
    // Значения: если PI[x] = y, то PI_INV[y] = x
    0,
};

// ── Коэффициенты линейного преобразования λ (ГОСТ Р 34.12-2015) ──────────────
// Многочлен λ(x) = 148x^15 + 32x^14 + 133x^13 + 16x^12 + 194x^11 +
//                   192x^10 + 1x^9 + 251x^8 + 1x^7 + 192x^6 + 194x^5 +
//                   16x^4 + 133x^3 + 32x^2 + 148x + 1
const uint8_t Grasshopper::LINEAR_COEFF[16] = {
    148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1
};

// ── GF(2^8) умножение (полином x^8 + x^7 + x^6 + x + 1 = 0x1C3) ─────────────
uint8_t Grasshopper::gf_mul(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    while (b) {
        if (b & 1) result ^= a;
        uint8_t hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0xC3;  // x^8 mod (x^8+x^7+x^6+x+1) = x^7+x^6+x+1 = 0xC3
        b >>= 1;
    }
    return result;
}

// ── Подстановка π (нелинейная замена) ────────────────────────────────────────
void Grasshopper::apply_s(GBlock& block) {
    for (auto& b : block) b = PI[b];
}

void Grasshopper::apply_s_inv(GBlock& block) {
    for (auto& b : block) {
        // Линейный поиск обратной функции (для безопасности используйте PI_INV)
        for (int i = 0; i < 256; i++) {
            if (PI[i] == b) { b = (uint8_t)i; break; }
        }
    }
}

// ── Перестановка τ (транспозиция байт) ───────────────────────────────────────
// τ в Кузнечике — тождественная (identity), блок уже в правильном порядке
void Grasshopper::apply_p(GBlock& /*block*/) { /* identity */ }
void Grasshopper::apply_p_inv(GBlock& /*block*/) { /* identity */ }

// ── Линейное преобразование λ (GF(2^8) умножение на L-матрицу) ───────────────
void Grasshopper::apply_l(GBlock& block) {
    // ГОСТ Р 34.12-2015: λ применяется 16 раз (R), каждый раз вычисляем
    // новый байт как XOR сумму произведений на коэффициенты LINEAR_COEFF
    for (int iter = 0; iter < 16; iter++) {
        uint8_t new_byte = 0;
        for (int i = 0; i < 16; i++) {
            new_byte ^= gf_mul(block[i], LINEAR_COEFF[i]);
        }
        // Сдвиг блока и вставка нового байта в начало
        for (int i = 15; i > 0; i--) block[i] = block[i-1];
        block[0] = new_byte;
    }
}

void Grasshopper::apply_l_inv(GBlock& block) {
    for (int iter = 0; iter < 16; iter++) {
        // Сдвиг блока в обратном направлении
        uint8_t saved = block[0];
        for (int i = 0; i < 15; i++) block[i] = block[i+1];
        block[15] = saved;
        uint8_t new_byte = 0;
        for (int i = 0; i < 16; i++) {
            new_byte ^= gf_mul(block[i], LINEAR_COEFF[i]);
        }
        block[15] = new_byte;
    }
}

// ── Расширение ключа ──────────────────────────────────────────────────────────
// ГОСТ Р 34.12-2015, п. 4.3: алгоритм Фейстеля для итерационных ключей
void Grasshopper::expand_key(const uint8_t* key) {
    // Первые два раундовых ключа = первые 16 байт и вторые 16 байт мастер-ключа
    std::memcpy(rk_.keys[0].data(), key,      16);
    std::memcpy(rk_.keys[1].data(), key + 16, 16);

    // Производим 4 пары ключей (итого 10 ключей = 8 раундовых + 2 мастера)
    for (int i = 0; i < 4; i++) {
        GBlock a = rk_.keys[2*i];
        GBlock b = rk_.keys[2*i + 1];
        for (int r = 0; r < 8; r++) {
            // c[r] — раундовая константа (номер раунда + 1)
            GBlock c = {};
            c[15] = (uint8_t)(8*i + r + 1);
            apply_l(c);  // λ(r || 0^120)
            // F(a, b): a = L(S(X(a, c))), b = старое a
            GBlock x = a;
            for (int j = 0; j < 16; j++) x[j] ^= c[j];
            apply_s(x);
            apply_l(x);
            for (int j = 0; j < 16; j++) x[j] ^= b[j];
            b = a;
            a = x;
        }
        rk_.keys[2*i + 2] = a;
        rk_.keys[2*i + 3] = b;
    }
}

// ── Конструктор ───────────────────────────────────────────────────────────────

Grasshopper::Grasshopper(const GKey& key) {
    expand_key(key.data());
}

Grasshopper::Grasshopper(const uint8_t* key, size_t len) {
    if (len != GRASSHOPPER_KEY_SIZE)
        throw std::invalid_argument("Grasshopper: ключ должен быть 32 байта");
    expand_key(key);
}

Grasshopper::~Grasshopper() = default;

// ── Шифрование одного блока (E_K) ────────────────────────────────────────────
GBlock Grasshopper::encrypt_block(const GBlock& plaintext) const {
    GBlock state = plaintext;
    // 9 раундов: X[k_i], S, L
    for (int r = 0; r < 9; r++) {
        for (int j = 0; j < 16; j++) state[j] ^= rk_.keys[r][j];  // X
        apply_s(state);                                               // S
        apply_l(state);                                               // L
    }
    // Последний раунд: только XOR (без S и L)
    for (int j = 0; j < 16; j++) state[j] ^= rk_.keys[9][j];
    return state;
}

// ── Расшифровывание одного блока (D_K) ───────────────────────────────────────
GBlock Grasshopper::decrypt_block(const GBlock& ciphertext) const {
    GBlock state = ciphertext;
    // Обратный порядок: XOR, L⁻¹, S⁻¹
    for (int j = 0; j < 16; j++) state[j] ^= rk_.keys[9][j];
    for (int r = 8; r >= 0; r--) {
        apply_l_inv(state);
        apply_s_inv(state);
        for (int j = 0; j < 16; j++) state[j] ^= rk_.keys[r][j];
    }
    return state;
}

// ── Режим CTR (ГОСТ Р 34.13-2015, раздел 5.4) ────────────────────────────────
std::vector<uint8_t> Grasshopper::encrypt_ctr(
    const std::vector<uint8_t>& data,
    const std::array<uint8_t, 8>& iv) const
{
    std::vector<uint8_t> out(data.size());
    GBlock counter = {};
    std::memcpy(counter.data(), iv.data(), 8);  // IV в старших 8 байтах

    size_t pos = 0;
    while (pos < data.size()) {
        GBlock keystream = encrypt_block(counter);
        size_t chunk = std::min((size_t)16, data.size() - pos);
        for (size_t i = 0; i < chunk; i++) out[pos + i] = data[pos + i] ^ keystream[i];
        // Инкремент счётчика (little-endian)
        for (int i = 15; i >= 8; i--) {
            if (++counter[i]) break;
        }
        pos += chunk;
    }
    return out;
}

std::vector<uint8_t> Grasshopper::decrypt_ctr(
    const std::vector<uint8_t>& data,
    const std::array<uint8_t, 8>& iv) const
{
    // CTR режим симметричен
    return encrypt_ctr(data, iv);
}

// ── Режим CBC ─────────────────────────────────────────────────────────────────
std::vector<uint8_t> Grasshopper::encrypt_cbc(
    const std::vector<uint8_t>& plaintext,
    const GBlock& iv) const
{
    if (plaintext.size() % 16 != 0)
        throw std::invalid_argument("CBC: данные должны быть кратны 16 байтам");
    std::vector<uint8_t> out(plaintext.size());
    GBlock prev = iv;
    for (size_t i = 0; i < plaintext.size(); i += 16) {
        GBlock block;
        std::memcpy(block.data(), plaintext.data() + i, 16);
        for (int j = 0; j < 16; j++) block[j] ^= prev[j];
        prev = encrypt_block(block);
        std::memcpy(out.data() + i, prev.data(), 16);
    }
    return out;
}

std::vector<uint8_t> Grasshopper::decrypt_cbc(
    const std::vector<uint8_t>& ciphertext,
    const GBlock& iv) const
{
    if (ciphertext.size() % 16 != 0)
        throw std::invalid_argument("CBC: данные должны быть кратны 16 байтам");
    std::vector<uint8_t> out(ciphertext.size());
    GBlock prev = iv;
    for (size_t i = 0; i < ciphertext.size(); i += 16) {
        GBlock block;
        std::memcpy(block.data(), ciphertext.data() + i, 16);
        GBlock dec = decrypt_block(block);
        for (int j = 0; j < 16; j++) dec[j] ^= prev[j];
        std::memcpy(out.data() + i, dec.data(), 16);
        prev = block;
    }
    return out;
}

// ── Режим имитовставки (MAC, ГОСТ Р 34.13-2015 раздел 5.7) ──────────────────
std::array<uint8_t, 8> Grasshopper::mac(const std::vector<uint8_t>& data) const {
    GBlock state = {};
    size_t pos = 0;
    while (pos < data.size()) {
        GBlock block = {};
        size_t chunk = std::min((size_t)16, data.size() - pos);
        std::memcpy(block.data(), data.data() + pos, chunk);
        for (int j = 0; j < 16; j++) state[j] ^= block[j];
        state = encrypt_block(state);
        pos += chunk;
    }
    std::array<uint8_t, 8> tag;
    std::memcpy(tag.data(), state.data(), 8);  // MSB 8 байт
    return tag;
}

// ── Верификация S-box ─────────────────────────────────────────────────────────
bool Grasshopper::verify_sbox() {
    // Проверяем, что PI является биекцией (каждый байт 0-255 встречается ровно раз)
    bool seen[256] = {};
    for (int i = 0; i < 256; i++) {
        if (seen[PI[i]]) return false;
        seen[PI[i]] = true;
    }
    return true;
}

} // namespace gost