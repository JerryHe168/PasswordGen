#include "../include/password_exporter.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include <sstream>
#include <random>
#include <chrono>
#include <thread>
#include <atomic>

#ifdef _WIN32
#include <windows.h>
#include <ntsecapi.h>
#pragma comment(lib, "advapi32.lib")
#endif

namespace {

std::mt19937& getSecureRandom() {
    static thread_local std::mt19937 rng;
    static thread_local bool initialized = false;
    
    if (!initialized) {
        std::vector<uint32_t> seed_data;
        
        auto now = std::chrono::high_resolution_clock::now().time_since_epoch();
        seed_data.push_back(static_cast<uint32_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(now).count() >> 32));
        seed_data.push_back(static_cast<uint32_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(now).count() & 0xFFFFFFFF));
        
        std::hash<std::thread::id> hasher;
        size_t thread_id = hasher(std::this_thread::get_id());
        seed_data.push_back(static_cast<uint32_t>(thread_id >> 32));
        seed_data.push_back(static_cast<uint32_t>(thread_id & 0xFFFFFFFF));
        
        int x;
        uint64_t stack_addr = reinterpret_cast<uint64_t>(&x);
        seed_data.push_back(static_cast<uint32_t>(stack_addr >> 32));
        seed_data.push_back(static_cast<uint32_t>(stack_addr & 0xFFFFFFFF));
        
        try {
            std::random_device rd;
            seed_data.push_back(rd());
            seed_data.push_back(rd());
        } catch (...) {}
        
#ifdef _WIN32
        HCRYPTPROV hProvider;
        if (CryptAcquireContextW(&hProvider, NULL, NULL, PROV_RSA_FULL, 
                                  CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
            std::vector<BYTE> buffer(16);
            if (CryptGenRandom(hProvider, static_cast<DWORD>(buffer.size()), buffer.data())) {
                for (size_t i = 0; i < buffer.size(); i += 4) {
                    uint32_t val = 0;
                    val |= static_cast<uint32_t>(buffer[i]) << 0;
                    val |= static_cast<uint32_t>(buffer[i + 1]) << 8;
                    val |= static_cast<uint32_t>(buffer[i + 2]) << 16;
                    val |= static_cast<uint32_t>(buffer[i + 3]) << 24;
                    seed_data.push_back(val);
                }
            }
            CryptReleaseContext(hProvider, 0);
        }
#endif
        
        static std::atomic<uint64_t> counter{0};
        uint64_t static_entropy = counter.fetch_add(1, std::memory_order_relaxed);
        seed_data.push_back(static_cast<uint32_t>(static_entropy >> 32));
        seed_data.push_back(static_cast<uint32_t>(static_entropy & 0xFFFFFFFF));
        
        std::seed_seq seed_seq(seed_data.begin(), seed_data.end());
        rng.seed(seed_seq);
        initialized = true;
    }
    
    return rng;
}

std::string generateRandomBytes(size_t length) {
    auto& rng = getSecureRandom();
    std::uniform_int_distribution<int> dist(0, 255);
    
    std::string result;
    result.reserve(length);
    for (size_t i = 0; i < length; ++i) {
        result += static_cast<char>(dist(rng));
    }
    return result;
}

std::string deriveKey(const std::string& key, const std::string& salt, size_t iterations = 1000) {
    std::string derived = key + salt;
    
    for (size_t iter = 0; iter < iterations; ++iter) {
        std::string next;
        next.reserve(derived.length() * 2);
        
        uint8_t carry = 0;
        for (size_t i = 0; i < derived.length(); ++i) {
            uint8_t c = static_cast<uint8_t>(derived[i]);
            
            c ^= carry;
            c = ((c << 1) | (c >> 7)) ^ 0x5A;
            carry = (c & 0x01) ? 0xFF : 0x00;
            
            next += static_cast<char>(c);
            next += static_cast<char>(c ^ 0xAA);
        }
        
        derived = next;
    }
    
    return derived;
}

const size_t SALT_LENGTH = 16;
const std::string MAGIC_HEADER = "PGEN";

std::string xorEncryptImproved(const std::string& data, const std::string& key) {
    if (key.empty()) {
        return data;
    }
    
    std::string salt = generateRandomBytes(SALT_LENGTH);
    std::string derived_key = deriveKey(key, salt);
    
    std::string result;
    result.reserve(MAGIC_HEADER.length() + 1 + SALT_LENGTH + data.length());
    
    result += MAGIC_HEADER;
    result += static_cast<char>(0x01);
    result += salt;
    
    for (size_t i = 0; i < data.length(); ++i) {
        result += static_cast<char>(data[i] ^ derived_key[i % derived_key.length()]);
    }
    
    return result;
}

bool isImprovedEncrypted(const std::string& data) {
    if (data.length() < MAGIC_HEADER.length() + 1 + SALT_LENGTH) {
        return false;
    }
    return data.substr(0, MAGIC_HEADER.length()) == MAGIC_HEADER;
}

std::string xorDecryptImproved(const std::string& data, const std::string& key) {
    if (!isImprovedEncrypted(data)) {
        return "";
    }
    
    size_t offset = MAGIC_HEADER.length();
    offset += 1;
    
    std::string salt = data.substr(offset, SALT_LENGTH);
    offset += SALT_LENGTH;
    
    std::string derived_key = deriveKey(key, salt);
    
    std::string result;
    result.reserve(data.length() - offset);
    
    for (size_t i = 0; i < data.length() - offset; ++i) {
        result += static_cast<char>(data[offset + i] ^ derived_key[i % derived_key.length()]);
    }
    
    return result;
}

std::string jsonEscape(const std::string& str) {
    std::ostringstream oss;
    
    for (char c : str) {
        switch (c) {
            case '"':
                oss << "\\\"";
                break;
            case '\\':
                oss << "\\\\";
                break;
            case '\n':
                oss << "\\n";
                break;
            case '\r':
                oss << "\\r";
                break;
            case '\t':
                oss << "\\t";
                break;
            case '\b':
                oss << "\\b";
                break;
            case '\f':
                oss << "\\f";
                break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    oss << "\\u" << std::hex << std::setw(4) << std::setfill('0') 
                        << static_cast<unsigned int>(static_cast<unsigned char>(c));
                } else {
                    oss << c;
                }
                break;
        }
    }
    
    return oss.str();
}

std::string csvEscape(const std::string& str) {
    bool needs_quoting = false;
    for (char c : str) {
        if (c == '"' || c == ',' || c == '\n' || c == '\r') {
            needs_quoting = true;
            break;
        }
    }
    
    if (!needs_quoting) {
        return str;
    }
    
    std::ostringstream oss;
    oss << "\"";
    for (char c : str) {
        if (c == '"') {
            oss << "\"\"";
        } else {
            oss << c;
        }
    }
    oss << "\"";
    return oss.str();
}

}

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
                content = xorEncryptImproved(content, xor_key);
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
        oss << csvEscape(pwd.password) << ",";
        oss << pwd.password.length() << ",";
        oss << csvEscape(strength_str) << ",";
        oss << pwd.entropy << ",";
        oss << csvEscape(pwd.strength_description) << std::endl;
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
        oss << "      \"password\": \"" << jsonEscape(pwd.password) << "\"," << std::endl;
        oss << "      \"length\": " << pwd.password.length() << "," << std::endl;
        oss << "      \"strength\": \"" << strength_str << "\"," << std::endl;
        oss << "      \"strength_cn\": \"" << jsonEscape(strength_cn) << "\"," << std::endl;
        oss << "      \"entropy\": " << pwd.entropy << "," << std::endl;
        oss << "      \"description\": \"" << jsonEscape(pwd.strength_description) << "\"" << std::endl;
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
