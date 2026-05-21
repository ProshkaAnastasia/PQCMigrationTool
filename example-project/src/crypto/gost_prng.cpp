// ─────────────────────────────────────────────────────────────────────────────
// ГПСЧ ГОСТ Р 34.20-2012 — CTR_DRBG на основе шифра Кузнечик
//
// Внутреннее состояние: ключ (32 байта) + счётчик V (16 байт) = 48 байт
// Начальная энтропия: /dev/urandom
// ─────────────────────────────────────────────────────────────────────────────
#include "crypto/gost_prng.hpp"
#include "crypto/grasshopper.hpp"
#include <openssl/rand.h>
#include <stdexcept>
#include <cstring>
#include <mutex>
#include <fstream>

namespace gost {

// ── GostPrng::Impl ────────────────────────────────────────────────────────────

struct GostPrng::Impl {
    std::array<uint8_t, 32> key;    // Текущий ключ Кузнечик
    std::array<uint8_t, 16> V;      // Счётчик CTR
    uint64_t request_count = 0;
    mutable std::mutex mtx;

    void seed_from_system() {
        if (RAND_bytes(key.data(), 32) != 1 || RAND_bytes(V.data(), 16) != 1) {
            // Fallback на /dev/urandom
            std::ifstream urng("/dev/urandom", std::ios::binary);
            urng.read(reinterpret_cast<char*>(key.data()), 32);
            urng.read(reinterpret_cast<char*>(V.data()), 16);
        }
    }

    void increment_V() {
        for (int i = 15; i >= 0; i--) {
            if (++V[i]) break;
        }
    }

    // CTR_DRBG_Generate согласно ГОСТ Р 34.20-2012
    void generate_block(uint8_t* out) {
        increment_V();
        Grasshopper cipher(key);
        GBlock block;
        std::memcpy(block.data(), V.data(), 16);
        GBlock enc = cipher.encrypt_block(block);
        std::memcpy(out, enc.data(), 16);
    }

    // Обновление внутреннего состояния (CTR_DRBG_Update)
    void update(const uint8_t* additional = nullptr, size_t add_len = 0) {
        uint8_t temp[48] = {};
        for (int i = 0; i < 3; i++) {
            generate_block(temp + i * 16);
        }
        if (additional && add_len > 0) {
            size_t xor_len = std::min(add_len, (size_t)48);
            for (size_t i = 0; i < xor_len; i++) temp[i] ^= additional[i];
        }
        std::memcpy(key.data(), temp,      32);
        std::memcpy(V.data(),   temp + 32, 16);
    }
};

GostPrng::GostPrng() : impl_(new Impl()) {
    impl_->seed_from_system();
    impl_->update();  // Перемешивание начального состояния
}

GostPrng::GostPrng(const std::vector<uint8_t>& seed) : impl_(new Impl()) {
    // Детерминированная инициализация из seed
    size_t copy = std::min(seed.size(), (size_t)48);
    std::memcpy(impl_->key.data(), seed.data(), std::min(copy, (size_t)32));
    if (copy > 32)
        std::memcpy(impl_->V.data(), seed.data() + 32, copy - 32);
    impl_->update();
}

GostPrng::~GostPrng() { delete impl_; }

std::vector<uint8_t> GostPrng::generate(size_t num_bytes) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    std::vector<uint8_t> out(num_bytes);
    generate(out.data(), num_bytes);
    return out;
}

void GostPrng::generate(uint8_t* buf, size_t num_bytes) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    size_t pos = 0;
    while (pos < num_bytes) {
        uint8_t block[16];
        impl_->generate_block(block);
        size_t chunk = std::min((size_t)16, num_bytes - pos);
        std::memcpy(buf + pos, block, chunk);
        pos += chunk;
    }
    impl_->update();  // Обновление состояния после генерации (CTR_DRBG)
    impl_->request_count++;

    // Автоматический пересев через 2^32 запроса
    if ((impl_->request_count & 0xFFFFFFFFULL) == 0) {
        reseed();
    }
}

void GostPrng::reseed(const std::vector<uint8_t>& additional_input) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    uint8_t entropy[32];
    if (RAND_bytes(entropy, 32) != 1) {
        std::ifstream urng("/dev/urandom", std::ios::binary);
        urng.read(reinterpret_cast<char*>(entropy), 32);
    }
    // Подмешиваем дополнительный входной материал
    if (!additional_input.empty()) {
        for (size_t i = 0; i < std::min(additional_input.size(), (size_t)32); i++) {
            entropy[i] ^= additional_input[i];
        }
    }
    impl_->update(entropy, 32);
    impl_->request_count = 0;
}

std::array<uint8_t, 32> GostPrng::generate_grasshopper_key() {
    std::array<uint8_t, 32> key;
    generate(key.data(), 32);
    return key;
}

std::array<uint8_t, 16> GostPrng::generate_iv() {
    std::array<uint8_t, 16> iv;
    generate(iv.data(), 16);
    return iv;
}

std::array<uint8_t, 8> GostPrng::generate_ctr_iv() {
    std::array<uint8_t, 8> iv;
    generate(iv.data(), 8);
    return iv;
}

uint64_t GostPrng::requests_since_reseed() const {
    return impl_->request_count;
}

// ── Глобальный ГПСЧ ───────────────────────────────────────────────────────────

GostPrng& global_prng() {
    static GostPrng instance;
    return instance;
}

std::vector<uint8_t> random_bytes(size_t n) {
    return global_prng().generate(n);
}

uint32_t random_uint32() {
    auto bytes = global_prng().generate(4);
    uint32_t val;
    std::memcpy(&val, bytes.data(), 4);
    return val;
}

uint64_t random_uint64() {
    auto bytes = global_prng().generate(8);
    uint64_t val;
    std::memcpy(&val, bytes.data(), 8);
    return val;
}

} // namespace gost