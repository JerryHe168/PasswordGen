#include "../include/password_exporter.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstdint>

const std::string PasswordExporter::base64_chars = 
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789+/";

bool PasswordExporter::exportToFile(const std::string& filename, 
                                      const std::vector<GeneratedPassword>& passwords,
                                      ExportFormat format,
                                      EncryptionType encryption,
                                      const std::string& xor_key) {
    std::string content = exportToString(passwords, format, encryption, xor_key);
    
    if (content.empty()) {
        return false;
    }
    
    std::ofstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }
    
    file << content;
    file.close();
    
    return file.good();
}

std::string PasswordExporter::exportToString(const std::vector<GeneratedPassword>& passwords,
                                                ExportFormat format,
                                                EncryptionType encryption,
                                                const std::string& xor_key) {
    std::string content;
    
    switch (format) {
        case ExportFormat::TXT:
            content = toTXT(passwords);
            break;
        case ExportFormat::CSV:
            content = toCSV(passwords);
            break;
        case ExportFormat::JSON:
            content = toJSON(passwords);
            break;
    }
    
    if (content.empty()) {
        return "";
    }
    
    switch (encryption) {
        case EncryptionType::XOR:
            if (!xor_key.empty()) {
                content = xorEncrypt(content, xor_key);
            }
            break;
        case EncryptionType::BASE64:
            content = base64Encode(content);
            break;
        case EncryptionType::NONE:
        default:
            break;
    }
    
    return content;
}

std::string PasswordExporter::toTXT(const std::vector<GeneratedPassword>& passwords) {
    std::ostringstream oss;
    
    oss << "========================================" << std::endl;
    oss << "           密码生成报告" << std::endl;
    oss << "========================================" << std::endl;
    oss << std::endl;
    
    for (size_t i = 0; i < passwords.size(); ++i) {
        const auto& pwd = passwords[i];
        
        oss << "密码 #" << (i + 1) << std::endl;
        oss << "----------------------------------------" << std::endl;
        oss << "密码:       " << pwd.password << std::endl;
        oss << "长度:       " << pwd.password.length() << " 字符" << std::endl;
        oss << "强度:       " << pwd.strength_description << std::endl;
        oss << "强度等级:   " << [pwd]() {
            switch (pwd.strength) {
                case PasswordStrength::WEAK: return "弱";
                case PasswordStrength::MEDIUM: return "中";
                case PasswordStrength::STRONG: return "强";
                case PasswordStrength::VERY_STRONG: return "极强";
                default: return "未知";
            }
        }() << std::endl;
        oss << "熵值:       " << pwd.entropy << " bits" << std::endl;
        oss << std::endl;
    }
    
    oss << "========================================" << std::endl;
    oss << "         共生成 " << passwords.size() << " 个密码" << std::endl;
    oss << "========================================" << std::endl;
    
    return oss.str();
}

std::string PasswordExporter::toCSV(const std::vector<GeneratedPassword>& passwords) {
    std::ostringstream oss;
    
    oss << "序号,密码,长度,强度等级,熵值(bits),强度描述" << std::endl;
    
    for (size_t i = 0; i < passwords.size(); ++i) {
        const auto& pwd = passwords[i];
        
        std::string strength_str;
        switch (pwd.strength) {
            case PasswordStrength::WEAK: strength_str = "弱"; break;
            case PasswordStrength::MEDIUM: strength_str = "中"; break;
            case PasswordStrength::STRONG: strength_str = "强"; break;
            case PasswordStrength::VERY_STRONG: strength_str = "极强"; break;
            default: strength_str = "未知"; break;
        }
        
        oss << (i + 1) << ",";
        oss << "\"" << pwd.password << "\"" << ",";
        oss << pwd.password.length() << ",";
        oss << strength_str << ",";
        oss << pwd.entropy << ",";
        oss << "\"" << pwd.strength_description << "\"" << std::endl;
    }
    
    return oss.str();
}

std::string PasswordExporter::toJSON(const std::vector<GeneratedPassword>& passwords) {
    std::ostringstream oss;
    
    oss << "{" << std::endl;
    oss << "  \"total_count\": " << passwords.size() << "," << std::endl;
    oss << "  \"passwords\": [" << std::endl;
    
    for (size_t i = 0; i < passwords.size(); ++i) {
        const auto& pwd = passwords[i];
        
        std::string strength_str;
        switch (pwd.strength) {
            case PasswordStrength::WEAK: strength_str = "weak"; break;
            case PasswordStrength::MEDIUM: strength_str = "medium"; break;
            case PasswordStrength::STRONG: strength_str = "strong"; break;
            case PasswordStrength::VERY_STRONG: strength_str = "very_strong"; break;
            default: strength_str = "unknown"; break;
        }
        
        std::string strength_cn;
        switch (pwd.strength) {
            case PasswordStrength::WEAK: strength_cn = "弱"; break;
            case PasswordStrength::MEDIUM: strength_cn = "中"; break;
            case PasswordStrength::STRONG: strength_cn = "强"; break;
            case PasswordStrength::VERY_STRONG: strength_cn = "极强"; break;
            default: strength_cn = "未知"; break;
        }
        
        oss << "    {" << std::endl;
        oss << "      \"index\": " << (i + 1) << "," << std::endl;
        oss << "      \"password\": \"" << pwd.password << "\"," << std::endl;
        oss << "      \"length\": " << pwd.password.length() << "," << std::endl;
        oss << "      \"strength\": \"" << strength_str << "\"," << std::endl;
        oss << "      \"strength_cn\": \"" << strength_cn << "\"," << std::endl;
        oss << "      \"entropy\": " << pwd.entropy << "," << std::endl;
        oss << "      \"description\": \"" << pwd.strength_description << "\"" << std::endl;
        oss << "    }";
        
        if (i < passwords.size() - 1) {
            oss << ",";
        }
        oss << std::endl;
    }
    
    oss << "  ]" << std::endl;
    oss << "}" << std::endl;
    
    return oss.str();
}

std::string PasswordExporter::xorEncrypt(const std::string& data, const std::string& key) {
    if (key.empty()) {
        return data;
    }
    
    std::string result;
    result.reserve(data.length());
    
    for (size_t i = 0; i < data.length(); ++i) {
        result += static_cast<char>(data[i] ^ key[i % key.length()]);
    }
    
    return result;
}

std::string PasswordExporter::base64Encode(const std::string& data) {
    std::string ret;
    int i = 0;
    int j = 0;
    uint8_t char_array_3[3];
    uint8_t char_array_4[4];
    size_t in_len = data.size();
    const unsigned char* bytes_to_encode = reinterpret_cast<const unsigned char*>(data.data());

    while (in_len--) {
        char_array_3[i++] = *(bytes_to_encode++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; (i <4) ; i++) {
                ret += base64_chars[char_array_4[i]];
            }
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 3; j++) {
            char_array_3[j] = '\0';
        }

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; (j < i + 1); j++) {
            ret += base64_chars[char_array_4[j]];
        }

        while ((i++ < 3)) {
            ret += '=';
        }
    }

    return ret;
}

std::string PasswordExporter::base64Decode(const std::string& encoded_string) {
    int in_len = static_cast<int>(encoded_string.size());
    int i = 0;
    int j = 0;
    int in_ = 0;
    uint8_t char_array_4[4], char_array_3[3];
    std::string ret;

    while (in_len-- && (encoded_string[in_] != '=') && 
           (isalnum(encoded_string[in_]) || (encoded_string[in_] == '+') || (encoded_string[in_] == '/'))) {
        char_array_4[i++] = encoded_string[in_];
        in_++;
        if (i ==4) {
            for (i = 0; i <4; i++) {
                char_array_4[i] = static_cast<uint8_t>(base64_chars.find(char_array_4[i]));
            }

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; (i < 3); i++) {
                ret += static_cast<char>(char_array_3[i]);
            }
            i = 0;
        }
    }

    if (i) {
        for (j = i; j <4; j++) {
            char_array_4[j] = 0;
        }

        for (j = 0; j <4; j++) {
            char_array_4[j] = static_cast<uint8_t>(base64_chars.find(char_array_4[j]));
        }

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (j = 0; (j < i - 1); j++) {
            ret += static_cast<char>(char_array_3[j]);
        }
    }

    return ret;
}
