// ─────────────────────────────────────────────────────────────────────────────
// Точка входа тестов ГОСТ криптографии
// ─────────────────────────────────────────────────────────────────────────────
#include "test_helper.hpp"
#include <iostream>

// Тесты регистрируются через вызов этих функций
void register_streebog_tests();
void register_grasshopper_tests();
void register_gost_sign_tests();

int main() {
    register_streebog_tests();
    register_grasshopper_tests();
    register_gost_sign_tests();

    int passed = 0, failed = 0;
    std::cout << "=== ГОСТ Тесты ===\n";
    for (auto& tc : test_registry()) {
        std::cout << "[ RUN ] " << tc.name << "\n";
        bool ok = false;
        try { ok = tc.fn(); } catch (const std::exception& e) {
            std::cerr << "  EXCEPTION: " << e.what() << "\n";
        }
        std::cout << (ok ? "[  OK ]" : "[FAIL ]") << " " << tc.name << "\n";
        if (ok) ++passed; else ++failed;
    }
    std::cout << "\n=== Результат: " << passed << " прошло, "
              << failed << " провалено из " << (passed + failed) << " ===\n";
    return failed > 0 ? 1 : 0;
}