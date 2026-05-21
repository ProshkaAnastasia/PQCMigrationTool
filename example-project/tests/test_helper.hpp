#pragma once
// Минимальный тестовый фреймворк без сторонних зависимостей
#include <iostream>
#include <string>
#include <vector>
#include <functional>

struct TestCase {
    std::string name;
    std::function<bool()> fn;
};

inline std::vector<TestCase>& test_registry() {
    static std::vector<TestCase> cases;
    return cases;
}

inline void add_test(const std::string& name, std::function<bool()> fn) {
    test_registry().push_back({name, std::move(fn)});
}

#define ASSERT_TRUE(cond) \
    if (!(cond)) { std::cerr << "  FAIL: " #cond "\n"; return false; }
#define ASSERT_EQ(a, b) \
    if (!((a) == (b))) { std::cerr << "  FAIL: " #a " != " #b "\n"; return false; }
#define ASSERT_NE(a, b) \
    if ((a) == (b)) { std::cerr << "  FAIL: expected != but " #a " == " #b "\n"; return false; }