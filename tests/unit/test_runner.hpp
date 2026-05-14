#pragma once
// Minimal test runner — no external dependencies required.
#include <iostream>
#include <vector>
#include <functional>
#include <stdexcept>
#include <string>

struct TestCase { std::string name; std::function<void()> fn; };

class TestSuite {
public:
    TestSuite(const std::string& name) : name_(name) {}
    void add(const std::string& name, std::function<void()> fn) { cases_.push_back({name,fn}); }
    int run() const {
        std::cout << "\n[Suite: " << name_ << "]\n";
        int pass=0, fail=0;
        for(auto& tc : cases_){
            try { tc.fn(); std::cout << "  [PASS] " << tc.name << "\n"; ++pass; }
            catch(const std::exception& e)
                { std::cout << "  [FAIL] " << tc.name << ": " << e.what() << "\n"; ++fail; }
            catch(...)
                { std::cout << "  [FAIL] " << tc.name << ": unknown exception\n"; ++fail; }
        }
        std::cout << "  Result: " << pass << "/" << (pass+fail) << " passed\n";
        return fail;
    }
private:
    std::string name_;
    std::vector<TestCase> cases_;
};

// Assertions
#define ASSERT_TRUE(cond) \
    do { if(!(cond)) throw std::runtime_error("ASSERT_TRUE failed: " #cond " at line " + std::to_string(__LINE__)); } while(0)
#define ASSERT_FALSE(cond) \
    do { if(cond) throw std::runtime_error("ASSERT_FALSE failed: " #cond " at line " + std::to_string(__LINE__)); } while(0)
#define ASSERT_EQ(a,b) \
    do { if((a)!=(b)) throw std::runtime_error(std::string("ASSERT_EQ: ") + std::to_string(a) + " != " + std::to_string(b) + " at line " + std::to_string(__LINE__)); } while(0)
#define ASSERT_GT(a,b) \
    do { if(!((a)>(b))) throw std::runtime_error(std::string("ASSERT_GT: ") + std::to_string(a) + " <= " + std::to_string(b) + " at line " + std::to_string(__LINE__)); } while(0)
#define ASSERT_GE(a,b) \
    do { if(!((a)>=(b))) throw std::runtime_error(std::string("ASSERT_GE: ") + std::to_string(a) + " < " + std::to_string(b) + " at line " + std::to_string(__LINE__)); } while(0)
#define ASSERT_NOT_EMPTY(v) \
    do { if((v).empty()) throw std::runtime_error("ASSERT_NOT_EMPTY: " #v " is empty at line " + std::to_string(__LINE__)); } while(0)
#define ASSERT_CONTAINS(str, sub) \
    do { if(std::string(str).find(sub)==std::string::npos) throw std::runtime_error(std::string("ASSERT_CONTAINS: '") + (sub) + "' not in '" + std::string(str).substr(0,80) + "' at line " + std::to_string(__LINE__)); } while(0)
