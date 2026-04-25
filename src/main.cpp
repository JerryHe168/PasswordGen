#include <iostream>
#include <iomanip>
#include <string>
#include <sstream>
#include <limits>

#ifdef _WIN32
#include <windows.h>
#endif

#include "../include/password_generator.h"
#include "../include/password_exporter.h"
#include "../include/argparse.h"

#ifdef _WIN32
static std::wstring utf8ToWide(const std::string& str) {
    if (str.empty()) return L"";
    
    int wideLen = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
    if (wideLen <= 0) return L"";
    
    std::wstring wideStr(wideLen - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &wideStr[0], wideLen);
    return wideStr;
}

static void consolePrint(const std::string& str) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hConsole == INVALID_HANDLE_VALUE) {
        std::cout << str;
        return;
    }
    
    DWORD mode;
    if (!GetConsoleMode(hConsole, &mode)) {
        std::cout << str;
        return;
    }
    
    std::wstring wideStr = utf8ToWide(str);
    if (wideStr.empty()) {
        std::cout << str;
        return;
    }
    
    DWORD written;
    WriteConsoleW(hConsole, wideStr.c_str(), static_cast<DWORD>(wideStr.length()), &written, nullptr);
}

static void consolePrintLn(const std::string& str) {
    consolePrint(str + "\n");
}

#define PRINT(x) consolePrint(x)
#define PRINTLN(x) consolePrintLn(x)

#else

#define PRINT(x) std::cout << x
#define PRINTLN(x) std::cout << x << std::endl

#endif

void setupConsoleEncoding() {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
}

template<typename T>
std::string toString(const T& value) {
    std::ostringstream oss;
    oss << value;
    return oss.str();
}

void printPassword(const GeneratedPassword& pwd, int index = -1) {
    PRINTLN("========================================");
    if (index > 0) {
        PRINTLN("           密码 #" + toString(index));
    } else {
        PRINTLN("            生成的密码");
    }
    PRINTLN("========================================");
    PRINTLN("");
    PRINTLN("密码:       " + pwd.password);
    PRINTLN("长度:       " + toString(pwd.password.length()) + " 字符");
    PRINTLN("");
    PRINTLN("强度评估:");
    
    std::string strength_bar;
    int strength_level = 0;
    switch (pwd.strength) {
        case PasswordStrength::WEAK: strength_level = 1; break;
        case PasswordStrength::MEDIUM: strength_level = 2; break;
        case PasswordStrength::STRONG: strength_level = 3; break;
        case PasswordStrength::VERY_STRONG: strength_level = 4; break;
    }
    
    for (int i = 0; i < 4; ++i) {
        if (i < strength_level) {
            strength_bar += "[]";
        } else {
            strength_bar += "..";
        }
    }
    
    std::string strength_str;
    switch (pwd.strength) {
        case PasswordStrength::WEAK: strength_str = "弱"; break;
        case PasswordStrength::MEDIUM: strength_str = "中"; break;
        case PasswordStrength::STRONG: strength_str = "强"; break;
        case PasswordStrength::VERY_STRONG: strength_str = "极强"; break;
    }
    
    PRINTLN("  等级:     " + strength_str + "  [" + strength_bar + "]");
    PRINTLN("  熵值:     " + toString(pwd.entropy) + " bits");
    PRINTLN("  描述:     " + pwd.strength_description);
    PRINTLN("");
}

void interactiveMode() {
    PasswordGenerator generator;
    PasswordConfig config;
    std::string input;
    
    PRINTLN("========================================");
    PRINTLN("        交互式密码生成器");
    PRINTLN("========================================");
    PRINTLN("");
    
    GenerationMode mode = GenerationMode::RANDOM;
    
    PRINTLN("请选择生成模式:");
    PRINTLN("  1. 随机密码 (推荐)");
    PRINTLN("  2. 易记密码");
    PRINTLN("  3. 模式密码");
    PRINTLN("");
    PRINT("请输入选项 (1-3, 默认: 1): ");
    std::getline(std::cin, input);
    
    if (input == "2") {
        mode = GenerationMode::MEMORABLE;
    } else if (input == "3") {
        mode = GenerationMode::PATTERN;
    }
    
    if (mode == GenerationMode::RANDOM) {
        PRINTLN("");
        PRINT("密码长度 (4-128, 默认: 12): ");
        std::getline(std::cin, input);
        if (!input.empty()) {
            try {
                int len = std::stoi(input);
                if (len >= 4 && len <= 128) {
                    config.length = len;
                }
            } catch (...) {}
        }
        
        PRINT("包含大写字母? (y/n, 默认: y): ");
        std::getline(std::cin, input);
        if (input == "n" || input == "N" || input == "no" || input == "NO") {
            config.use_uppercase = false;
        }
        
        PRINT("包含小写字母? (y/n, 默认: y): ");
        std::getline(std::cin, input);
        if (input == "n" || input == "N" || input == "no" || input == "NO") {
            config.use_lowercase = false;
        }
        
        PRINT("包含数字? (y/n, 默认: y): ");
        std::getline(std::cin, input);
        if (input == "n" || input == "N" || input == "no" || input == "NO") {
            config.use_numbers = false;
        }
        
        PRINT("包含特殊符号? (y/n, 默认: y): ");
        std::getline(std::cin, input);
        if (input == "n" || input == "N" || input == "no" || input == "NO") {
            config.use_symbols = false;
        }
        
        if (!config.use_uppercase && !config.use_lowercase && 
            !config.use_numbers && !config.use_symbols) {
            PRINTLN("");
            PRINTLN("警告: 所有字符集都被禁用，将启用默认设置");
            config.use_uppercase = true;
            config.use_lowercase = true;
            config.use_numbers = true;
            config.use_symbols = true;
        }
    } else if (mode == GenerationMode::MEMORABLE) {
        PRINTLN("");
        PRINT("单词数量 (默认: 2): ");
        std::getline(std::cin, input);
        if (!input.empty()) {
            try {
                int val = std::stoi(input);
                if (val >= 1) config.memorable_words = val;
            } catch (...) {}
        }
        
        PRINT("数字数量 (默认: 2): ");
        std::getline(std::cin, input);
        if (!input.empty()) {
            try {
                int val = std::stoi(input);
                if (val >= 0) config.memorable_numbers = val;
            } catch (...) {}
        }
        
        PRINT("符号数量 (默认: 1): ");
        std::getline(std::cin, input);
        if (!input.empty()) {
            try {
                int val = std::stoi(input);
                if (val >= 0) config.memorable_symbols = val;
            } catch (...) {}
        }
    } else if (mode == GenerationMode::PATTERN) {
        PRINTLN("");
        PRINTLN("模式格式说明:");
        PRINTLN("  L/l - 字母 (大写或小写)");
        PRINTLN("  U   - 大写字母");
        PRINTLN("  D/N - 数字");
        PRINTLN("  S   - 特殊符号");
        PRINTLN("");
        PRINTLN("示例: LLNNS (字母-字母-数字-数字-符号)");
        PRINT("请输入模式: ");
        std::getline(std::cin, input);
        config.pattern = input;
        
        if (config.pattern.empty()) {
            PRINTLN("使用默认模式: LLNNS");
            config.pattern = "LLNNS";
        }
    }
    
    int batch_count = 1;
    PRINTLN("");
    PRINT("生成数量 (1-1000, 默认: 1): ");
    std::getline(std::cin, input);
    if (!input.empty()) {
        try {
            int count = std::stoi(input);
            if (count >= 1 && count <= 1000) {
                batch_count = count;
            }
        } catch (...) {}
    }
    
    PRINTLN("");
    PRINTLN("正在生成密码...");
    PRINTLN("");
    
    auto passwords = generator.generateBatch(batch_count, config, mode);
    
    for (size_t i = 0; i < passwords.size(); ++i) {
        printPassword(passwords[i], static_cast<int>(i + 1));
    }
    
    PRINT("是否保存到文件? (y/n, 默认: n): ");
    std::getline(std::cin, input);
    if (input == "y" || input == "Y" || input == "yes" || input == "YES") {
        PRINT("请输入文件名 (如: passwords.txt): ");
        std::getline(std::cin, input);
        
        if (!input.empty()) {
            ExportFormat format = ExportFormat::TXT;
            EncryptionType encryption = EncryptionType::NONE;
            std::string xor_key;
            
            PRINT("输出格式 (1=TXT, 2=CSV, 3=JSON, 默认: 1): ");
            std::string fmt_input;
            std::getline(std::cin, fmt_input);
            if (fmt_input == "2") format = ExportFormat::CSV;
            else if (fmt_input == "3") format = ExportFormat::JSON;
            
            PRINT("加密方式 (1=无, 2=XOR, 3=Base64, 默认: 1): ");
            std::string enc_input;
            std::getline(std::cin, enc_input);
            if (enc_input == "2") {
                encryption = EncryptionType::XOR;
                PRINT("请输入XOR密钥: ");
                std::getline(std::cin, xor_key);
            } else if (enc_input == "3") {
                encryption = EncryptionType::BASE64;
            }
            
            if (PasswordExporter::exportToFile(input, passwords, format, encryption, xor_key)) {
                PRINTLN("");
                PRINTLN("密码已成功保存到: " + input);
            } else {
                PRINTLN("");
                PRINTLN("错误: 无法保存到文件");
            }
        }
    }
}

int main(int argc, char* argv[]) {
    setupConsoleEncoding();
    
    ArgumentParser parser("passwordgen", "1.0.0");
    auto args = parser.parse(argc, argv);
    
    if (args.show_help) {
        parser.showHelp();
        return 0;
    }
    
    if (args.show_version) {
        parser.showVersion();
        return 0;
    }
    
    PasswordGenerator generator;
    
    if (args.interactive) {
        interactiveMode();
        return 0;
    }
    
    if (args.evaluate_only && !args.password_to_evaluate.empty()) {
        auto strength = generator.evaluateStrength(args.password_to_evaluate);
        int entropy = generator.calculateEntropy(args.password_to_evaluate);
        std::string desc = generator.strengthToDescription(strength);
        
        GeneratedPassword pwd;
        pwd.password = args.password_to_evaluate;
        pwd.strength = strength;
        pwd.entropy = entropy;
        pwd.strength_description = desc;
        
        printPassword(pwd);
        return 0;
    }
    
    if (args.mode == GenerationMode::PATTERN && args.config.pattern.empty()) {
        PRINTLN("错误: 模式密码需要指定 -p 或 --pattern 参数");
        PRINTLN("使用 -h 或 --help 查看帮助");
        return 1;
    }
    
    bool chars_enabled = args.config.use_uppercase || args.config.use_lowercase || 
                         args.config.use_numbers || args.config.use_symbols;
    
    if (!chars_enabled) {
        PRINTLN("错误: 至少需要启用一种字符类型");
        PRINTLN("使用 -h 或 --help 查看帮助");
        return 1;
    }
    
    auto passwords = generator.generateBatch(args.batch_count, args.config, args.mode);
    
    for (size_t i = 0; i < passwords.size(); ++i) {
        printPassword(passwords[i], args.batch_count > 1 ? static_cast<int>(i + 1) : -1);
    }
    
    if (!args.output_file.empty()) {
        if (PasswordExporter::exportToFile(args.output_file, passwords, 
                                             args.export_format, args.encryption, 
                                             args.xor_key)) {
            PRINTLN("密码已成功保存到: " + args.output_file);
        } else {
            PRINTLN("错误: 无法保存到文件");
            return 1;
        }
    }
    
    return 0;
}
