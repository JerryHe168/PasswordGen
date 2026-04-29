#include "password_generator.h"
#include "password_exporter.h"
#include <iostream>
#include <cassert>
#include <string>
#include <set>
#include <algorithm>
#include <sstream>
#include <stdexcept>

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) void test_##name()
#define RUN_TEST(name) \
    do { \
        std::cout << "  测试: " << #name << " ... "; \
        try { \
            test_##name(); \
            std::cout << "通过" << std::endl; \
            tests_passed++; \
        } catch (const std::exception& e) { \
            std::cout << "失败: " << e.what() << std::endl; \
            tests_failed++; \
        } \
    } while(0)

#define ASSERT(condition, message) \
    if (!(condition)) { throw std::runtime_error(message); }

#define ASSERT_EQUAL(actual, expected, message) \
    if ((actual) != (expected)) { \
        std::ostringstream oss; \
        oss << message << " (期望: " << expected << ", 实际: " << actual << ")"; \
        throw std::runtime_error(oss.str()); \
    }

TEST(random_password_length) {
    PasswordGenerator gen;
    PasswordConfig config;
    
    config.length = 4;
    auto result = gen.generate(config, GenerationMode::RANDOM);
    ASSERT_EQUAL(result.password.length(), 4, "密码长度应为4");
    
    config.length = 128;
    result = gen.generate(config, GenerationMode::RANDOM);
    ASSERT_EQUAL(result.password.length(), 128, "密码长度应为128");
}

TEST(random_password_charset) {
    PasswordGenerator gen;
    PasswordConfig config;
    
    config.use_uppercase = true;
    config.use_lowercase = false;
    config.use_numbers = false;
    config.use_symbols = false;
    config.length = 20;
    
    for (int i = 0; i < 100; ++i) {
        auto result = gen.generate(config, GenerationMode::RANDOM);
        for (char c : result.password) {
            ASSERT(std::isupper(static_cast<unsigned char>(c)), 
                   "密码应只包含大写字母");
        }
    }
    
    config.use_uppercase = false;
    config.use_numbers = true;
    for (int i = 0; i < 100; ++i) {
        auto result = gen.generate(config, GenerationMode::RANDOM);
        for (char c : result.password) {
            ASSERT(std::isdigit(static_cast<unsigned char>(c)), 
                   "密码应只包含数字");
        }
    }
}

TEST(random_password_all_charsets) {
    PasswordGenerator gen;
    PasswordConfig config;
    config.length = 8;
    config.use_uppercase = true;
    config.use_lowercase = true;
    config.use_numbers = true;
    config.use_symbols = true;
    
    bool has_upper = false, has_lower = false, has_digit = false, has_symbol = false;
    
    for (int i = 0; i < 1000; ++i) {
        auto result = gen.generate(config, GenerationMode::RANDOM);
        for (char c : result.password) {
            if (std::isupper(static_cast<unsigned char>(c))) has_upper = true;
            else if (std::islower(static_cast<unsigned char>(c))) has_lower = true;
            else if (std::isdigit(static_cast<unsigned char>(c))) has_digit = true;
            else has_symbol = true;
        }
        if (has_upper && has_lower && has_digit && has_symbol) break;
    }
    
    ASSERT(has_upper, "应生成包含大写字母的密码");
    ASSERT(has_lower, "应生成包含小写字母的密码");
    ASSERT(has_digit, "应生成包含数字的密码");
    ASSERT(has_symbol, "应生成包含符号的密码");
}

TEST(memorable_password_structure) {
    PasswordGenerator gen;
    PasswordConfig config;
    config.memorable_words = 2;
    config.memorable_numbers = 2;
    config.memorable_symbols = 1;
    config.use_uppercase = true;
    config.use_lowercase = true;
    config.use_numbers = true;
    config.use_symbols = true;
    
    auto result = gen.generate(config, GenerationMode::MEMORABLE);
    
    int digit_count = 0;
    int symbol_count = 0;
    for (char c : result.password) {
        if (std::isdigit(static_cast<unsigned char>(c))) digit_count++;
        else if (!std::isalpha(static_cast<unsigned char>(c))) symbol_count++;
    }
    
    ASSERT_EQUAL(digit_count, 2, "应包含2个数字");
    ASSERT_EQUAL(symbol_count, 1, "应包含1个符号");
    ASSERT(std::isupper(static_cast<unsigned char>(result.password[0])), 
           "首字母应大写");
}

TEST(pattern_password) {
    PasswordGenerator gen;
    PasswordConfig config;
    
    config.pattern = "LLNNS";
    auto result = gen.generate(config, GenerationMode::PATTERN);
    ASSERT_EQUAL(result.password.length(), 5, "模式密码长度应为5");
    ASSERT(std::isalpha(static_cast<unsigned char>(result.password[0])), "第1位应为字母");
    ASSERT(std::isalpha(static_cast<unsigned char>(result.password[1])), "第2位应为字母");
    ASSERT(std::isdigit(static_cast<unsigned char>(result.password[2])), "第3位应为数字");
    ASSERT(std::isdigit(static_cast<unsigned char>(result.password[3])), "第4位应为数字");
    
    config.pattern = "UUDD";
    result = gen.generate(config, GenerationMode::PATTERN);
    ASSERT(std::isupper(static_cast<unsigned char>(result.password[0])), "第1位应为大写");
    ASSERT(std::isupper(static_cast<unsigned char>(result.password[1])), "第2位应为大写");
    ASSERT(std::isdigit(static_cast<unsigned char>(result.password[2])), "第3位应为数字");
    ASSERT(std::isdigit(static_cast<unsigned char>(result.password[3])), "第4位应为数字");
}

TEST(password_strength_weak) {
    PasswordGenerator gen;
    
    auto weak1 = gen.evaluateStrength("aaaa");
    ASSERT_EQUAL(static_cast<int>(weak1), static_cast<int>(PasswordStrength::WEAK), "短密码应为弱强度");
    
    auto weak2 = gen.evaluateStrength("aaaaaaaa");
    ASSERT_EQUAL(static_cast<int>(weak2), static_cast<int>(PasswordStrength::WEAK), "只有小写字母应为弱强度");
}

TEST(password_strength_medium) {
    PasswordGenerator gen;
    
    auto medium = gen.evaluateStrength("Password123");
    ASSERT(medium == PasswordStrength::MEDIUM || medium == PasswordStrength::STRONG, 
           "混合密码强度应至少为中等");
}

TEST(password_strength_strong) {
    PasswordGenerator gen;
    
    auto strong = gen.evaluateStrength("MyP@ssw0rd123!");
    ASSERT(strong == PasswordStrength::STRONG || strong == PasswordStrength::VERY_STRONG, 
           "复杂密码应为强或极强");
}

TEST(entropy_calculation) {
    PasswordGenerator gen;
    
    auto entropy1 = gen.calculateEntropy("aaaa");
    ASSERT(entropy1 < 20, "简单密码熵值应较低");
    
    auto entropy2 = gen.calculateEntropy("aA1!bB2@cC3#dD4$");
    ASSERT(entropy2 > 60, "复杂密码熵值应较高");
}

TEST(batch_generation) {
    PasswordGenerator gen;
    PasswordConfig config;
    
    auto batch = gen.generateBatch(10, config, GenerationMode::RANDOM);
    ASSERT_EQUAL(batch.size(), 10, "批量生成应返回10个密码");
    
    std::set<std::string> unique_passwords;
    for (const auto& pwd : batch) {
        unique_passwords.insert(pwd.password);
    }
    
    ASSERT(unique_passwords.size() >= 5, "批量生成的密码应大部分不同");
}

TEST(json_escape) {
    PasswordGenerator gen;
    PasswordConfig config;
    config.length = 4;
    config.use_uppercase = false;
    config.use_lowercase = false;
    config.use_numbers = true;
    config.use_symbols = false;
    
    GeneratedPassword test_pwd;
    test_pwd.password = "test\"quote\\backslash";
    test_pwd.strength = PasswordStrength::STRONG;
    test_pwd.strength_description = "测试描述";
    test_pwd.entropy = 50;
    
    std::vector<GeneratedPassword> passwords = {test_pwd};
    
    auto json = PasswordExporter::exportToString(passwords, ExportFormat::JSON, EncryptionType::NONE, "");
    
    ASSERT(json.find("test\\\"quote\\\\backslash") != std::string::npos, 
           "JSON应正确转义特殊字符");
}

TEST(xor_encryption_decryption) {
    PasswordGenerator gen;
    PasswordConfig config;
    config.length = 16;
    
    auto original = gen.generate(config, GenerationMode::RANDOM);
    std::vector<GeneratedPassword> passwords = {original};
    
    std::string key = "test_key_123";
    
    auto encrypted = PasswordExporter::exportToString(passwords, ExportFormat::JSON, EncryptionType::XOR, key);
    
    ASSERT(encrypted.length() > 0, "加密结果不应为空");
    ASSERT(encrypted.substr(0, 4) == "PGEN", "加密数据应以魔数开头");
}

TEST(secure_clear) {
    std::string sensitive = "MySecretPassword123!";
    std::string original = sensitive;
    
    secureClear(sensitive);
    
    bool is_cleared = true;
    for (char c : sensitive) {
        if (c != '\0') {
            is_cleared = false;
            break;
        }
    }
    
    ASSERT(is_cleared || sensitive.length() == 0, "secureClear应清除字符串内容");
    ASSERT_EQUAL(sensitive.length(), original.length(), "secureClear不应改变字符串长度");
}

TEST(word_list_operations) {
    PasswordGenerator gen;
    
    size_t initial_count = gen.getWordCount();
    ASSERT(initial_count > 0, "初始单词列表不应为空");
    
    gen.resetWordList();
    ASSERT_EQUAL(gen.getWordCount(), initial_count, "重置后单词数应恢复");
}

TEST(random_number_generator_uniqueness) {
    PasswordGenerator gen1;
    PasswordGenerator gen2;
    
    PasswordConfig config;
    config.length = 20;
    
    std::set<std::string> passwords;
    
    for (int i = 0; i < 100; ++i) {
        auto p1 = gen1.generate(config, GenerationMode::RANDOM);
        auto p2 = gen2.generate(config, GenerationMode::RANDOM);
        passwords.insert(p1.password);
        passwords.insert(p2.password);
    }
    
    ASSERT(passwords.size() >= 150, "随机生成器应产生大部分不同的密码");
}

TEST(invalid_configs) {
    PasswordGenerator gen;
    PasswordConfig config;
    
    config.length = 3;
    auto result = gen.generate(config, GenerationMode::RANDOM);
    ASSERT(result.password.empty(), "长度小于4应返回空");
    
    config.length = 129;
    result = gen.generate(config, GenerationMode::RANDOM);
    ASSERT(result.password.empty(), "长度大于128应返回空");
    
    config.length = 10;
    config.use_uppercase = false;
    config.use_lowercase = false;
    config.use_numbers = false;
    config.use_symbols = false;
    result = gen.generate(config, GenerationMode::RANDOM);
    ASSERT(result.password.empty(), "未启用任何字符集应返回空");
}

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "      PasswordGen 单元测试" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    
    std::cout << "[1] 随机密码测试" << std::endl;
    RUN_TEST(random_password_length);
    RUN_TEST(random_password_charset);
    RUN_TEST(random_password_all_charsets);
    RUN_TEST(invalid_configs);
    
    std::cout << std::endl << "[2] 易记密码测试" << std::endl;
    RUN_TEST(memorable_password_structure);
    RUN_TEST(word_list_operations);
    
    std::cout << std::endl << "[3] 模式密码测试" << std::endl;
    RUN_TEST(pattern_password);
    
    std::cout << std::endl << "[4] 强度评估测试" << std::endl;
    RUN_TEST(password_strength_weak);
    RUN_TEST(password_strength_medium);
    RUN_TEST(password_strength_strong);
    RUN_TEST(entropy_calculation);
    
    std::cout << std::endl << "[5] 批量生成测试" << std::endl;
    RUN_TEST(batch_generation);
    
    std::cout << std::endl << "[6] 导出功能测试" << std::endl;
    RUN_TEST(json_escape);
    RUN_TEST(xor_encryption_decryption);
    
    std::cout << std::endl << "[7] 安全功能测试" << std::endl;
    RUN_TEST(secure_clear);
    RUN_TEST(random_number_generator_uniqueness);
    
    std::cout << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "测试完成" << std::endl;
    std::cout << "  通过: " << tests_passed << std::endl;
    std::cout << "  失败: " << tests_failed << std::endl;
    std::cout << "========================================" << std::endl;
    
    return tests_failed > 0 ? 1 : 0;
}
