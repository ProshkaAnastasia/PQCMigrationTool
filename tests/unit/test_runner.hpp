#pragma once
#include <iostream>
#include <vector>
#include <functional>
#include <stdexcept>
#include <string>
#include <sstream>

struct TestCase {
    std::string name;
    std::function<void()> fn;
};

class TestSuite {
public:
    TestSuite(const std::string& name) : name_(name) {}
    void add(const std::string& name, std::function<void()> fn) { cases_.push_back({name, fn}); }
    int run() const
    {
        std::cout << "\n[Suite: " << name_ << "]\n";
        int pass = 0, fail = 0;
        for (auto& tc : cases_) {
            try {
                tc.fn();
                std::cout << "  [PASS] " << tc.name << "\n";
                ++pass;
            } catch (const std::exception& e) {
                std::cout << "  [FAIL] " << tc.name << ": " << e.what() << "\n";
                ++fail;
            } catch (...) {
                std::cout << "  [FAIL] " << tc.name << ": unknown exception\n";
                ++fail;
            }
        }
        std::cout << "  Result: " << pass << "/" << (pass + fail) << " passed\n";
        return fail;
    }

private:
    std::string name_;
    std::vector<TestCase> cases_;
};

template <typename T>
inline std::string test_to_string(const T& value)
{
    std::ostringstream oss;
    oss << value;
    return oss.str();
}

inline std::string test_to_string(const std::string& value)
{
    return value;
}

inline std::string test_to_string(const char* value)
{
    return value ? std::string(value) : std::string("(null)");
}

#define ASSERT_TRUE(cond)                                                                        \
    do {                                                                                         \
        if (!(cond))                                                                             \
            throw std::runtime_error(std::string("ASSERT_TRUE failed: ") + #cond + " at line " + \
                                     std::to_string(__LINE__));                                  \
    } while (0)

#define ASSERT_FALSE(cond)                                                                        \
    do {                                                                                          \
        if (cond)                                                                                 \
            throw std::runtime_error(std::string("ASSERT_FALSE failed: ") + #cond + " at line " + \
                                     std::to_string(__LINE__));                                   \
    } while (0)

#define ASSERT_EQ(a, b)                                                                            \
    do {                                                                                           \
        auto _a = (a);                                                                             \
        auto _b = (b);                                                                             \
        if (!(_a == _b))                                                                           \
            throw std::runtime_error(std::string("ASSERT_EQ: ") + test_to_string(_a) + " != " +    \
                                     test_to_string(_b) + " at line " + std::to_string(__LINE__)); \
    } while (0)

#define ASSERT_GT(a, b)                                                                            \
    do {                                                                                           \
        auto _a = (a);                                                                             \
        auto _b = (b);                                                                             \
        if (!(_a > _b))                                                                            \
            throw std::runtime_error(std::string("ASSERT_GT: ") + test_to_string(_a) + " <= " +    \
                                     test_to_string(_b) + " at line " + std::to_string(__LINE__)); \
    } while (0)

#define ASSERT_GE(a, b)                                                                            \
    do {                                                                                           \
        auto _a = (a);                                                                             \
        auto _b = (b);                                                                             \
        if (!(_a >= _b))                                                                           \
            throw std::runtime_error(std::string("ASSERT_GE: ") + test_to_string(_a) + " < " +     \
                                     test_to_string(_b) + " at line " + std::to_string(__LINE__)); \
    } while (0)

#define ASSERT_NOT_EMPTY(v)                                                            \
    do {                                                                               \
        if ((v).empty())                                                               \
            throw std::runtime_error(std::string("ASSERT_NOT_EMPTY: ") + #v +          \
                                     " is empty at line " + std::to_string(__LINE__)); \
    } while (0)

#define ASSERT_CONTAINS(str, sub)                                                                 \
    do {                                                                                          \
        auto _s = std::string(str);                                                               \
        auto _sub = std::string(sub);                                                             \
        if (_s.find(_sub) == std::string::npos)                                                   \
            throw std::runtime_error(std::string("ASSERT_CONTAINS: '") + _sub + "' not in '" +    \
                                     _s.substr(0, 80) + "' at line " + std::to_string(__LINE__)); \
    } while (0)
