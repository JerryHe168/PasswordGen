#include "../include/argparse.h"
#include <iostream>
#include <algorithm>
#include <cctype>
#include <sstream>

ArgumentParser::ArgumentParser(const std::string& program_name, const std::string& version)
    : program_name(program_name), version(version) {
    initializeArguments();
}

void ArgumentParser::initializeArguments() {
    addArgument("-h", "--help", "显示帮助信息", true, false, "");
    addArgument("-v", "--version", "显示版本信息", true, false, "");
    
    addArgument("-m", "--mode", "生成模式: random(随机), memorable(易记), pattern(模式) [默认: random]", 
                false, false, "random");
    addArgument("-l", "--length", "密码长度 (4-128) [默认: 12]", false, false, "12");
    addArgument("-p", "--pattern", "模式密码的格式 (如: L-L-N-N-S 表示字母-字母-数字-数字-符号)", 
                false, false, "");
    
    addArgument("-u", "--uppercase", "包含大写字母 (默认启用，使用 -no-u 禁用)", true, false, "true");
    addArgument("-no-u", "--no-uppercase", "禁用大写字母", true, false, "");
    addArgument("-c", "--lowercase", "包含小写字母 (默认启用，使用 -no-c 禁用)", true, false, "true");
    addArgument("-no-c", "--no-lowercase", "禁用小写字母", true, false, "");
    addArgument("-n", "--numbers", "包含数字 (默认启用，使用 -no-n 禁用)", true, false, "true");
    addArgument("-no-n", "--no-numbers", "禁用数字", true, false, "");
    addArgument("-s", "--symbols", "包含特殊符号 (默认启用，使用 -no-s 禁用)", true, false, "true");
    addArgument("-no-s", "--no-symbols", "禁用特殊符号", true, false, "");
    
    addArgument("-w", "--words", "易记密码的单词数量 [默认: 2]", false, false, "2");
    addArgument("-dn", "--digits", "易记密码的数字数量 [默认: 2]", false, false, "2");
    addArgument("-ds", "--dsymbols", "易记密码的符号数量 [默认: 1]", false, false, "1");
    
    addArgument("-b", "--batch", "批量生成密码的数量 (1-1000) [默认: 1]", false, false, "1");
    
    addArgument("-e", "--evaluate", "评估现有密码的强度 (格式: -e \"password\")", false, false, "");
    
    addArgument("-o", "--output", "输出文件路径", false, false, "");
    addArgument("-f", "--format", "输出格式: txt, csv, json [默认: txt]", false, false, "txt");
    
    addArgument("-x", "--xor", "使用XOR加密保存 (需要提供密钥)", false, false, "");
    addArgument("-b64", "--base64", "使用Base64编码保存", true, false, "");
    
    addArgument("-i", "--interactive", "进入交互式模式", true, false, "");
}

void ArgumentParser::addArgument(const std::string& short_name,
                                  const std::string& long_name,
                                  const std::string& description,
                                  bool is_flag,
                                  bool required,
                                  const std::string& default_value,
                                  std::function<void(const std::string&)> action) {
    Argument arg;
    arg.short_name = short_name;
    arg.long_name = long_name;
    arg.description = description;
    arg.is_flag = is_flag;
    arg.required = required;
    arg.default_value = default_value;
    arg.value = default_value;
    arg.action = action;
    
    arguments.push_back(arg);
    
    if (!short_name.empty()) {
        argument_map[short_name] = arguments.size() - 1;
    }
    if (!long_name.empty()) {
        argument_map[long_name] = arguments.size() - 1;
    }
}

std::string ArgumentParser::trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\n\r\"'");
    if (start == std::string::npos) return "";
    
    size_t end = s.find_last_not_of(" \t\n\r\"'");
    return s.substr(start, end - start + 1);
}

ParsedArgs ArgumentParser::parse(int argc, char* argv[]) {
    ParsedArgs result;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        auto it = argument_map.find(arg);
        if (it == argument_map.end()) {
            if (arg.substr(0, 2) == "--") {
                std::cerr << "错误: 未知选项 " << arg << std::endl;
            } else if (arg.size() > 2 && arg[0] == '-') {
                std::cerr << "错误: 未知选项 " << arg << std::endl;
            }
            continue;
        }
        
        Argument& argument = arguments[it->second];
        
        if (argument.is_flag) {
            argument.value = "true";
            
            if (arg == "--no-uppercase" || arg == "-no-u") {
                for (auto& a : arguments) {
                    if (a.long_name == "--uppercase" || a.short_name == "-u") {
                        a.value = "false";
                    }
                }
            }
            if (arg == "--no-lowercase" || arg == "-no-c") {
                for (auto& a : arguments) {
                    if (a.long_name == "--lowercase" || a.short_name == "-c") {
                        a.value = "false";
                    }
                }
            }
            if (arg == "--no-numbers" || arg == "-no-n") {
                for (auto& a : arguments) {
                    if (a.long_name == "--numbers" || a.short_name == "-n") {
                        a.value = "false";
                    }
                }
            }
            if (arg == "--no-symbols" || arg == "-no-s") {
                for (auto& a : arguments) {
                    if (a.long_name == "--symbols" || a.short_name == "-s") {
                        a.value = "false";
                    }
                }
            }
        } else {
            if (i + 1 < argc) {
                argument.value = argv[i + 1];
                i++;
            } else {
                std::cerr << "错误: 选项 " << arg << " 需要参数" << std::endl;
            }
        }
    }
    
    for (const auto& arg : arguments) {
        if (arg.short_name == "-h" || arg.long_name == "--help") {
            result.show_help = (arg.value == "true");
        }
        if (arg.short_name == "-v" || arg.long_name == "--version") {
            result.show_version = (arg.value == "true");
        }
        if (arg.short_name == "-i" || arg.long_name == "--interactive") {
            result.interactive = (arg.value == "true");
        }
        if (arg.short_name == "-b64" || arg.long_name == "--base64") {
            if (arg.value == "true") {
                result.encryption = EncryptionType::BASE64;
            }
        }
        
        if (arg.short_name == "-m" || arg.long_name == "--mode") {
            std::string mode = arg.value;
            std::transform(mode.begin(), mode.end(), mode.begin(), ::tolower);
            if (mode == "memorable") {
                result.mode = GenerationMode::MEMORABLE;
            } else if (mode == "pattern") {
                result.mode = GenerationMode::PATTERN;
            } else {
                result.mode = GenerationMode::RANDOM;
            }
        }
        
        if (arg.short_name == "-l" || arg.long_name == "--length") {
            try {
                int len = std::stoi(arg.value);
                if (len >= 4 && len <= 128) {
                    result.config.length = len;
                }
            } catch (...) {}
        }
        
        if (arg.short_name == "-p" || arg.long_name == "--pattern") {
            result.config.pattern = arg.value;
        }
        
        if (arg.short_name == "-u" || arg.long_name == "--uppercase") {
            result.config.use_uppercase = (arg.value == "true");
        }
        if (arg.short_name == "-c" || arg.long_name == "--lowercase") {
            result.config.use_lowercase = (arg.value == "true");
        }
        if (arg.short_name == "-n" || arg.long_name == "--numbers") {
            result.config.use_numbers = (arg.value == "true");
        }
        if (arg.short_name == "-s" || arg.long_name == "--symbols") {
            result.config.use_symbols = (arg.value == "true");
        }
        
        if (arg.short_name == "-w" || arg.long_name == "--words") {
            try {
                int val = std::stoi(arg.value);
                if (val >= 1) result.config.memorable_words = val;
            } catch (...) {}
        }
        if (arg.short_name == "-dn" || arg.long_name == "--digits") {
            try {
                int val = std::stoi(arg.value);
                if (val >= 0) result.config.memorable_numbers = val;
            } catch (...) {}
        }
        if (arg.short_name == "-ds" || arg.long_name == "--dsymbols") {
            try {
                int val = std::stoi(arg.value);
                if (val >= 0) result.config.memorable_symbols = val;
            } catch (...) {}
        }
        
        if (arg.short_name == "-b" || arg.long_name == "--batch") {
            try {
                int count = std::stoi(arg.value);
                if (count >= 1 && count <= 1000) {
                    result.batch_count = count;
                }
            } catch (...) {}
        }
        
        if (arg.short_name == "-e" || arg.long_name == "--evaluate") {
            if (!arg.value.empty()) {
                result.evaluate_only = true;
                result.password_to_evaluate = trim(arg.value);
            }
        }
        
        if (arg.short_name == "-o" || arg.long_name == "--output") {
            result.output_file = arg.value;
        }
        if (arg.short_name == "-f" || arg.long_name == "--format") {
            std::string fmt = arg.value;
            std::transform(fmt.begin(), fmt.end(), fmt.begin(), ::tolower);
            if (fmt == "csv") {
                result.export_format = ExportFormat::CSV;
            } else if (fmt == "json") {
                result.export_format = ExportFormat::JSON;
            } else {
                result.export_format = ExportFormat::TXT;
            }
        }
        
        if (arg.short_name == "-x" || arg.long_name == "--xor") {
            if (!arg.value.empty()) {
                result.encryption = EncryptionType::XOR;
                result.xor_key = arg.value;
            }
        }
    }
    
    return result;
}

void ArgumentParser::showHelp() const {
    std::cout << "========================================" << std::endl;
    std::cout << "  PasswordGen - 密码生成器 v" << version << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    std::cout << "用法: " << program_name << " [选项]" << std::endl;
    std::cout << std::endl;
    std::cout << "基础选项:" << std::endl;
    std::cout << "  -h, --help         显示帮助信息" << std::endl;
    std::cout << "  -v, --version      显示版本信息" << std::endl;
    std::cout << "  -i, --interactive  进入交互式模式" << std::endl;
    std::cout << std::endl;
    std::cout << "生成模式:" << std::endl;
    std::cout << "  -m, --mode <模式>  选择生成模式: random(随机), memorable(易记), pattern(模式)" << std::endl;
    std::cout << "  -l, --length <N>   密码长度 (4-128，默认: 12)" << std::endl;
    std::cout << "  -p, --pattern <格式> 模式密码格式 (如: L-L-N-N-S)" << std::endl;
    std::cout << std::endl;
    std::cout << "字符集选项:" << std::endl;
    std::cout << "  -u, --uppercase    包含大写字母 (默认启用)" << std::endl;
    std::cout << "  -no-u, --no-uppercase  禁用大写字母" << std::endl;
    std::cout << "  -c, --lowercase    包含小写字母 (默认启用)" << std::endl;
    std::cout << "  -no-c, --no-lowercase  禁用小写字母" << std::endl;
    std::cout << "  -n, --numbers      包含数字 (默认启用)" << std::endl;
    std::cout << "  -no-n, --no-numbers    禁用数字" << std::endl;
    std::cout << "  -s, --symbols      包含特殊符号 (默认启用)" << std::endl;
    std::cout << "  -no-s, --no-symbols    禁用特殊符号" << std::endl;
    std::cout << std::endl;
    std::cout << "易记密码选项:" << std::endl;
    std::cout << "  -w, --words <N>    单词数量 (默认: 2)" << std::endl;
    std::cout << "  -dn, --digits <N>  数字数量 (默认: 2)" << std::endl;
    std::cout << "  -ds, --dsymbols <N> 符号数量 (默认: 1)" << std::endl;
    std::cout << std::endl;
    std::cout << "批量生成:" << std::endl;
    std::cout << "  -b, --batch <N>    批量生成 N 个密码 (1-1000，默认: 1)" << std::endl;
    std::cout << std::endl;
    std::cout << "密码评估:" << std::endl;
    std::cout << "  -e, --evaluate <密码>  评估现有密码的强度" << std::endl;
    std::cout << std::endl;
    std::cout << "输出选项:" << std::endl;
    std::cout << "  -o, --output <文件>   输出到文件" << std::endl;
    std::cout << "  -f, --format <格式>   输出格式: txt, csv, json (默认: txt)" << std::endl;
    std::cout << "  -x, --xor <密钥>      使用XOR加密保存" << std::endl;
    std::cout << "  -b64, --base64        使用Base64编码保存" << std::endl;
    std::cout << std::endl;
    showExamples();
}

void ArgumentParser::showVersion() const {
    std::cout << "PasswordGen v" << version << std::endl;
    std::cout << "一个功能完善的C++命令行密码生成器工具" << std::endl;
    std::cout << "支持多种生成策略和输出方式，跨平台" << std::endl;
}

void ArgumentParser::showExamples() const {
    std::cout << "========================================" << std::endl;
    std::cout << "           使用示例" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    std::cout << "1. 生成随机密码 (默认12字符，包含所有字符类型):" << std::endl;
    std::cout << "   " << program_name << std::endl;
    std::cout << std::endl;
    std::cout << "2. 生成16位随机密码，仅包含字母和数字:" << std::endl;
    std::cout << "   " << program_name << " -l 16 -no-s" << std::endl;
    std::cout << std::endl;
    std::cout << "3. 生成易记密码 (单词+数字+符号):" << std::endl;
    std::cout << "   " << program_name << " -m memorable -w 3 -dn 3 -ds 2" << std::endl;
    std::cout << std::endl;
    std::cout << "4. 生成模式密码 (如: 字母-字母-数字-数字-符号):" << std::endl;
    std::cout << "   " << program_name << " -m pattern -p \"LLNNS\"" << std::endl;
    std::cout << std::endl;
    std::cout << "5. 批量生成10个密码并保存到文件:" << std::endl;
    std::cout << "   " << program_name << " -b 10 -o passwords.txt" << std::endl;
    std::cout << std::endl;
    std::cout << "6. 导出为JSON格式:" << std::endl;
    std::cout << "   " << program_name << " -b 5 -f json -o passwords.json" << std::endl;
    std::cout << std::endl;
    std::cout << "7. 使用XOR加密保存:" << std::endl;
    std::cout << "   " << program_name << " -o secret.txt -x mySecretKey" << std::endl;
    std::cout << std::endl;
    std::cout << "8. 评估现有密码强度:" << std::endl;
    std::cout << "   " << program_name << " -e \"MyP@ssw0rd123\"" << std::endl;
    std::cout << std::endl;
    std::cout << "9. 进入交互式模式:" << std::endl;
    std::cout << "   " << program_name << " -i" << std::endl;
    std::cout << std::endl;
}
