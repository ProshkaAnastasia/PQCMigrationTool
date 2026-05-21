#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// Электронная цифровая подпись ГОСТ Р 34.10-2012
//
// Алгоритм:
//   1. Хэширование сообщения алгоритмом Стрибог (ГОСТ Р 34.11-2012)
//   2. Генерация случайного k ∈ [1, n-1]
//   3. Вычисление C = k·G (точка на эллиптической кривой)
//   4. r = Cx mod n (если r = 0, повторить с другим k)
//   5. e = h mod n, если e = 0, то e = 1  (h — хэш сообщения)
//   6. s = (r·d + k·e) mod n (d — закрытый ключ)
//   7. Подпись = (r || s) — две компоненты по 32 или 64 байта
//
// Параметры кривых (TC26):
//   256-бит: id-tc26-gost-3410-2012-256-paramSetA (RFC 7836)
//   512-бит: id-tc26-gost-3410-2012-512-paramSetA (RFC 7836)
//            id-tc26-gost-3410-2012-512-paramSetB
//            id-tc26-gost-3410-2012-512-paramSetC
//
// Стандарты:
//   ГОСТ Р 34.10-2012  — основной стандарт ЭЦП
//   RFC 7091            — PKIX с ГОСТ подписью
//   RFC 7836            — параметры кривых TC26
//   ГОСТ Р 34.10-94    — УСТАРЕВШИЙ (Diffie-Hellman на конечных полях)
//
// Постквантовый статус: УЯЗВИМ (алгоритм Шора эффективно решает DLOG на ЭК).
//   РЕКОМЕНДАЦИЯ ТК 26: использовать как ПЕРЕХОДНЫЙ механизм.
//   В долгосрочной перспективе — переход на постквантовые подписи:
//   ML-DSA (CRYSTALS-Dilithium, FIPS 204) или SLH-DSA (FIPS 205).
// ─────────────────────────────────────────────────────────────────────────────
#include <cstdint>
#include <vector>
#include <string>
#include <memory>

namespace gost {

// Параметры эллиптических кривых согласно ГОСТ Р 34.10-2012 / RFC 7836
enum class GostCurve {
    TC26_GOST_3410_12_256_A,  // 256-бит, paramSetA — РЕКОМЕНДОВАН ТК 26
    TC26_GOST_3410_12_512_A,  // 512-бит, paramSetA
    TC26_GOST_3410_12_512_B,  // 512-бит, paramSetB — РЕКОМЕНДОВАН ТК 26
    TC26_GOST_3410_12_512_C,  // 512-бит, paramSetC
    CRYPTOPRO_2001_A,         // 256-бит, для совместимости с ГОСТ Р 34.10-2001
    CRYPTOPRO_2001_B,
    CRYPTOPRO_2001_C,
    TEST_2001,                // Тестовый набор (RFC 4357) — НЕ для продуктива!
};

// Размер подписи
constexpr size_t SIGN_SIZE_256 = 64;   // Для 256-бит кривых: (r || s), по 32 байта каждый
constexpr size_t SIGN_SIZE_512 = 128;  // Для 512-бит кривых: (r || s), по 64 байта каждый

class GostPrivateKey;
class GostPublicKey;

// Пара ключей ГОСТ Р 34.10-2012
class GostKeyPair {
public:
    static GostKeyPair generate(GostCurve curve = GostCurve::TC26_GOST_3410_12_256_A);

    // Сериализация/десериализация (DER формат)
    std::vector<uint8_t> private_key_der() const;
    std::vector<uint8_t> public_key_der() const;
    static GostKeyPair from_private_der(const std::vector<uint8_t>& der,
                                        GostCurve curve);

    // PEM формат
    std::string private_key_pem() const;
    std::string public_key_pem() const;

    GostCurve curve() const;
    const std::vector<uint8_t>& private_key_raw() const;  // d
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> public_key_raw() const; // (Qx, Qy)

    ~GostKeyPair();
    GostKeyPair(GostKeyPair&&) noexcept;
    GostKeyPair& operator=(GostKeyPair&&) noexcept;
    GostKeyPair(const GostKeyPair&) = delete;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    explicit GostKeyPair(std::unique_ptr<Impl>);
};

// Интерфейс подписания ГОСТ Р 34.10-2012
class GostSigner {
public:
    explicit GostSigner(const GostKeyPair& keypair);
    ~GostSigner();

    // Подписание данных
    // Использует Стрибог-256 (для 256-бит кривых) или Стрибог-512 (для 512-бит)
    std::vector<uint8_t> sign(const uint8_t* data, size_t len) const;
    std::vector<uint8_t> sign(const std::vector<uint8_t>& data) const;

    // Прямое подписание предвычисленного хэша
    std::vector<uint8_t> sign_hash(const std::vector<uint8_t>& hash) const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Интерфейс проверки подписи ГОСТ Р 34.10-2012
class GostVerifier {
public:
    // Инициализация публичным ключом из DER
    explicit GostVerifier(const std::vector<uint8_t>& public_key_der,
                          GostCurve curve = GostCurve::TC26_GOST_3410_12_256_A);

    explicit GostVerifier(const GostKeyPair& keypair);
    ~GostVerifier();

    // Проверка подписи
    bool verify(const uint8_t* data, size_t data_len,
                const std::vector<uint8_t>& signature) const;
    bool verify(const std::vector<uint8_t>& data,
                const std::vector<uint8_t>& signature) const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Параметры кривых (для инспекции и отладки)
struct CurveParams {
    std::string name;     // Наименование
    std::string oid;      // OID кривой
    std::string p;        // Простое число p (модуль поля) — hex
    std::string a;        // Коэффициент a — hex
    std::string b;        // Коэффициент b — hex
    std::string gx;       // Координата x порождающей точки G — hex
    std::string gy;       // Координата y порождающей точки G — hex
    std::string n;        // Порядок n подгруппы, порождённой G — hex
    size_t      bits;     // Длина в битах
};

const CurveParams& get_curve_params(GostCurve curve);

} // namespace gost