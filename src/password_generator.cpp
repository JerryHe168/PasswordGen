#include "../include/password_generator.h"
#include <algorithm>
#include <cctype>
#include <cmath>
#include <chrono>
#include <unordered_set>
#include <random>
#include <thread>
#include <atomic>
#include <fstream>
#include <sstream>

#ifdef _WIN32
#include <windows.h>
#include <ntsecapi.h>
#pragma comment(lib, "advapi32.lib")
#endif

namespace {

uint64_t getThreadIdEntropy() {
    std::hash<std::thread::id> hasher;
    return static_cast<uint64_t>(hasher(std::this_thread::get_id()));
}

uint64_t getTimeEntropy() {
    auto now = std::chrono::high_resolution_clock::now();
    auto duration = now.time_since_epoch();
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(duration).count()
    );
}

uint64_t getStackAddressEntropy() {
    int x;
    return reinterpret_cast<uint64_t>(&x);
}

uint64_t getRandomDeviceEntropy() {
    try {
        std::random_device rd;
        return (static_cast<uint64_t>(rd()) << 32) | static_cast<uint32_t>(rd());
    } catch (...) {
        return 0;
    }
}

#ifdef _WIN32
bool useWindowsCryptoAPI(std::vector<uint32_t>& seed_data) {
    HCRYPTPROV hProvider;
    if (CryptAcquireContextW(&hProvider, NULL, NULL, PROV_RSA_FULL, 
                              CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        std::vector<BYTE> buffer(32);
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
        return true;
    }
    return false;
}
#endif

}

PasswordGenerator::PasswordGenerator() {
    std::vector<uint32_t> seed_data;
    
    uint64_t time_entropy = getTimeEntropy();
    seed_data.push_back(static_cast<uint32_t>(time_entropy >> 32));
    seed_data.push_back(static_cast<uint32_t>(time_entropy & 0xFFFFFFFF));
    
    uint64_t thread_entropy = getThreadIdEntropy();
    seed_data.push_back(static_cast<uint32_t>(thread_entropy >> 32));
    seed_data.push_back(static_cast<uint32_t>(thread_entropy & 0xFFFFFFFF));
    
    uint64_t stack_entropy = getStackAddressEntropy();
    seed_data.push_back(static_cast<uint32_t>(stack_entropy >> 32));
    seed_data.push_back(static_cast<uint32_t>(stack_entropy & 0xFFFFFFFF));
    
    uint64_t rd_entropy = getRandomDeviceEntropy();
    if (rd_entropy != 0) {
        seed_data.push_back(static_cast<uint32_t>(rd_entropy >> 32));
        seed_data.push_back(static_cast<uint32_t>(rd_entropy & 0xFFFFFFFF));
    }
    
#ifdef _WIN32
    useWindowsCryptoAPI(seed_data);
#endif
    
    static std::atomic<uint64_t> counter{0};
    uint64_t static_entropy = counter.fetch_add(1, std::memory_order_relaxed);
    seed_data.push_back(static_cast<uint32_t>(static_entropy >> 32));
    seed_data.push_back(static_cast<uint32_t>(static_entropy & 0xFFFFFFFF));
    
    std::seed_seq seed_seq(seed_data.begin(), seed_data.end());
    rng.seed(seed_seq);
    
    initializeWordList();
}

namespace {

void secureClearImpl(char* p, size_t len) noexcept {
    if (!p || len == 0) {
        return;
    }
    
    for (size_t i = 0; i < len; ++i) {
        *reinterpret_cast<volatile char*>(&p[i]) = '\0';
    }
    std::atomic_thread_fence(std::memory_order_seq_cst);
    
    for (size_t i = 0; i < len; ++i) {
        *reinterpret_cast<volatile char*>(&p[i]) = static_cast<char>(0x55);
    }
    std::atomic_thread_fence(std::memory_order_seq_cst);
    
    for (size_t i = 0; i < len; ++i) {
        *reinterpret_cast<volatile char*>(&p[i]) = static_cast<char>(0xAA);
    }
    std::atomic_thread_fence(std::memory_order_seq_cst);
    
    for (size_t i = 0; i < len; ++i) {
        *reinterpret_cast<volatile char*>(&p[i]) = '\0';
    }
    std::atomic_thread_fence(std::memory_order_seq_cst);
}

}

void secureClear(std::string& str) noexcept {
    if (str.empty()) {
        return;
    }
    
    size_t len = str.size();
    char* p = &str[0];
    
    secureClearImpl(p, len);
}

bool PasswordGenerator::isValidWord(const std::string& word) {
    if (word.length() < MIN_WORD_LENGTH || word.length() > MAX_WORD_LENGTH) {
        return false;
    }
    
    for (char c : word) {
        if (!std::isalpha(static_cast<unsigned char>(c))) {
            return false;
        }
    }
    
    return true;
}

void PasswordGenerator::initializeWordList() {
    word_list = {
        "apple", "orange", "banana", "grape", "mango", "peach", "cherry", "berry",
        "river", "ocean", "lake", "water", "stream", "wave", "cloud", "rain",
        "sunset", "sunrise", "moon", "star", "light", "dark", "night", "day",
        "mountain", "hill", "valley", "forest", "tree", "leaf", "flower", "plant",
        "happy", "joy", "love", "peace", "calm", "brave", "strong", "wise",
        "swift", "quick", "fast", "slow", "gentle", "kind", "bright", "shiny",
        "stone", "rock", "gold", "silver", "bronze", "steel", "iron", "copper",
        "fire", "flame", "heat", "cold", "ice", "snow", "wind", "storm",
        "blue", "red", "green", "yellow", "purple", "orange", "white", "black",
        "bird", "fish", "cat", "dog", "wolf", "bear", "eagle", "hawk",
        "spring", "summer", "autumn", "winter", "season", "time", "hour", "minute",
        "north", "south", "east", "west", "home", "road", "path", "way",
        "book", "pen", "paper", "write", "read", "learn", "teach", "study",
        "music", "song", "dance", "sing", "play", "art", "paint", "draw",
        "heart", "soul", "mind", "body", "spirit", "dream", "hope", "wish",
        "power", "force", "energy", "magic", "mystic", "secret", "hidden", "open"
    };
    using_default_list_ = true;
}

bool PasswordGenerator::loadWordList(const std::string& filepath) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::ifstream file(filepath);
    if (!file.is_open()) {
        return false;
    }
    
    std::vector<std::string> new_words;
    std::string line;
    
    while (std::getline(file, line)) {
        size_t start = 0;
        size_t end = line.length();
        
        while (start < end && std::isspace(static_cast<unsigned char>(line[start]))) {
            start++;
        }
        while (end > start && std::isspace(static_cast<unsigned char>(line[end - 1]))) {
            end--;
        }
        
        if (start < end) {
            std::string word = line.substr(start, end - start);
            if (isValidWord(word)) {
                new_words.push_back(word);
            }
        }
    }
    
    file.close();
    
    if (new_words.size() < MIN_WORDS_REQUIRED) {
        return false;
    }
    
    word_list.swap(new_words);
    current_word_list_path = filepath;
    using_default_list_ = false;
    return true;
}

size_t PasswordGenerator::getWordCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return word_list.size();
}

void PasswordGenerator::resetWordList() {
    std::lock_guard<std::mutex> lock(mutex_);
    word_list.clear();
    initializeWordList();
    current_word_list_path.clear();
}

std::string PasswordGenerator::getCurrentWordListPath() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return current_word_list_path;
}

void PasswordGenerator::ensureWordListLoaded(const PasswordConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!config.word_list_path.empty()) {
        if (config.word_list_path != current_word_list_path) {
            std::vector<std::string> new_words;
            std::string line;
            
            std::ifstream file(config.word_list_path);
            if (file.is_open()) {
                while (std::getline(file, line)) {
                    size_t start = 0;
                    size_t end = line.length();
                    
                    while (start < end && std::isspace(static_cast<unsigned char>(line[start]))) {
                        start++;
                    }
                    while (end > start && std::isspace(static_cast<unsigned char>(line[end - 1]))) {
                        end--;
                    }
                    
                    if (start < end) {
                        std::string word = line.substr(start, end - start);
                        if (isValidWord(word)) {
                            new_words.push_back(word);
                        }
                    }
                }
                file.close();
                
                if (new_words.size() >= MIN_WORDS_REQUIRED) {
                    word_list.swap(new_words);
                    current_word_list_path = config.word_list_path;
                    using_default_list_ = false;
                    return;
                }
            }
            
            if (word_list.empty()) {
                initializeWordList();
            }
        }
    } else if (!current_word_list_path.empty()) {
        word_list.clear();
        initializeWordList();
        current_word_list_path.clear();
    }
    
    if (word_list.empty()) {
        initializeWordList();
    }
}

GeneratedPassword PasswordGenerator::generate(const PasswordConfig& config, GenerationMode mode) {
    GeneratedPassword result;
    
    if (mode == GenerationMode::MEMORABLE) {
        ensureWordListLoaded(config);
    }
    
    switch (mode) {
        case GenerationMode::RANDOM:
            result.password = generateRandom(config);
            break;
        case GenerationMode::MEMORABLE:
            result.password = generateMemorable(config);
            break;
        case GenerationMode::PATTERN:
            result.password = generatePattern(config);
            break;
    }
    
    result.strength = evaluateStrength(result.password);
    result.entropy = calculateEntropy(result.password);
    result.strength_description = strengthToDescription(result.strength);
    
    return result;
}

std::vector<GeneratedPassword> PasswordGenerator::generateBatch(int count, const PasswordConfig& config, GenerationMode mode) {
    std::vector<GeneratedPassword> results;
    results.reserve(count);
    
    for (int i = 0; i < count; ++i) {
        results.push_back(generate(config, mode));
    }
    
    return results;
}

std::string PasswordGenerator::generateRandom(const PasswordConfig& config) {
    if (config.length < 4 || config.length > 128) {
        return "";
    }
    
    std::string available = getAvailableChars(config);
    if (available.empty()) {
        return "";
    }
    
    int enabled_types = 0;
    if (config.use_uppercase) enabled_types++;
    if (config.use_lowercase) enabled_types++;
    if (config.use_numbers) enabled_types++;
    if (config.use_symbols) enabled_types++;
    
    if (enabled_types == 0) {
        return "";
    }
    
    int actual_length = config.length;
    
    std::string password;
    password.reserve(actual_length);
    
    std::vector<std::string> forced_chars;
    if (config.use_uppercase) forced_chars.push_back(getUppercaseChars());
    if (config.use_lowercase) forced_chars.push_back(getLowercaseChars());
    if (config.use_numbers) forced_chars.push_back(getNumberChars());
    if (config.use_symbols) forced_chars.push_back(getSymbolChars());
    
    if (static_cast<int>(forced_chars.size()) > actual_length) {
        std::shuffle(forced_chars.begin(), forced_chars.end(), rng);
        forced_chars.resize(actual_length);
    }
    
    for (const auto& charset : forced_chars) {
        password += getRandomChar(charset);
    }
    
    while (password.length() < static_cast<size_t>(actual_length)) {
        password += getRandomChar(available);
    }
    
    std::shuffle(password.begin(), password.end(), rng);
    
    return password;
}

std::string PasswordGenerator::generateMemorable(const PasswordConfig& config) {
    std::string password;
    
    for (int i = 0; i < config.memorable_words; ++i) {
        std::string word = getRandomWord();
        
        if (config.use_uppercase && i == 0) {
            word[0] = std::toupper(word[0]);
        }
        
        password += word;
    }
    
    if (config.use_numbers && config.memorable_numbers > 0) {
        std::string numbers = getNumberChars();
        for (int i = 0; i < config.memorable_numbers; ++i) {
            password += getRandomChar(numbers);
        }
    }
    
    if (config.use_symbols && config.memorable_symbols > 0) {
        std::string symbols = getSymbolChars();
        for (int i = 0; i < config.memorable_symbols; ++i) {
            password += getRandomChar(symbols);
        }
    }
    
    return password;
}

std::string PasswordGenerator::generatePattern(const PasswordConfig& config) {
    if (config.pattern.empty()) {
        return "";
    }
    
    std::string password;
    std::string uppercase = getUppercaseChars();
    std::string lowercase = getLowercaseChars();
    std::string numbers = getNumberChars();
    std::string symbols = getSymbolChars();
    
    for (char c : config.pattern) {
        switch (std::toupper(c)) {
            case 'L':
                password += getRandomChar(std::string("") + uppercase + lowercase);
                break;
            case 'U':
                password += getRandomChar(uppercase);
                break;
            case 'D':
            case 'N':
                password += getRandomChar(numbers);
                break;
            case 'S':
                password += getRandomChar(symbols);
                break;
            default:
                password += c;
                break;
        }
    }
    
    return password;
}

PasswordStrength PasswordGenerator::evaluateStrength(const std::string& password) {
    int score = 0;
    int length = static_cast<int>(password.length());
    
    if (length >= 8) score += 1;
    if (length >= 12) score += 1;
    if (length >= 16) score += 1;
    
    bool has_upper = false, has_lower = false;
    bool has_number = false, has_symbol = false;
    
    for (char c : password) {
        if (std::isupper(c)) has_upper = true;
        else if (std::islower(c)) has_lower = true;
        else if (std::isdigit(c)) has_number = true;
        else has_symbol = true;
    }
    
    if (has_upper) score += 1;
    if (has_lower) score += 1;
    if (has_number) score += 1;
    if (has_symbol) score += 1;
    
    int variety_count = (has_upper ? 1 : 0) + (has_lower ? 1 : 0) + 
                        (has_number ? 1 : 0) + (has_symbol ? 1 : 0);
    
    if (variety_count == 4 && length >= 12) {
        score += 1;
    }
    
    if (score <= 3) return PasswordStrength::WEAK;
    if (score <= 5) return PasswordStrength::MEDIUM;
    if (score <= 7) return PasswordStrength::STRONG;
    return PasswordStrength::VERY_STRONG;
}

int PasswordGenerator::calculateEntropy(const std::string& password) {
    if (password.empty()) return 0;
    
    int char_set_size = 0;
    bool has_upper = false, has_lower = false;
    bool has_number = false, has_symbol = false;
    
    for (char c : password) {
        if (std::isupper(c)) has_upper = true;
        else if (std::islower(c)) has_lower = true;
        else if (std::isdigit(c)) has_number = true;
        else has_symbol = true;
    }
    
    if (has_upper) char_set_size += 26;
    if (has_lower) char_set_size += 26;
    if (has_number) char_set_size += 10;
    if (has_symbol) char_set_size += 33;
    
    if (char_set_size == 0) return 0;
    
    double entropy = password.length() * std::log2(char_set_size);
    
    return static_cast<int>(std::round(entropy));
}

std::string PasswordGenerator::strengthToString(PasswordStrength strength) {
    switch (strength) {
        case PasswordStrength::WEAK: return "弱";
        case PasswordStrength::MEDIUM: return "中";
        case PasswordStrength::STRONG: return "强";
        case PasswordStrength::VERY_STRONG: return "极强";
        default: return "未知";
    }
}

std::string PasswordGenerator::strengthToDescription(PasswordStrength strength) {
    switch (strength) {
        case PasswordStrength::WEAK:
            return "容易被破解，建议增加长度和字符种类";
        case PasswordStrength::MEDIUM:
            return "有一定安全性，但仍可被暴力破解";
        case PasswordStrength::STRONG:
            return "安全性良好，适合大多数场景";
        case PasswordStrength::VERY_STRONG:
            return "安全性极高，适合高敏感场景";
        default:
            return "未知强度";
    }
}

std::string PasswordGenerator::getUppercaseChars() const {
    return "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
}

std::string PasswordGenerator::getLowercaseChars() const {
    return "abcdefghijklmnopqrstuvwxyz";
}

std::string PasswordGenerator::getNumberChars() const {
    return "0123456789";
}

std::string PasswordGenerator::getSymbolChars() const {
    return "!@#$%^&*()_+-=[]{}|;:'\",.<>?/`~";
}

std::string PasswordGenerator::getAvailableChars(const PasswordConfig& config) const {
    std::string available;
    
    if (config.use_uppercase) available += getUppercaseChars();
    if (config.use_lowercase) available += getLowercaseChars();
    if (config.use_numbers) available += getNumberChars();
    if (config.use_symbols) available += getSymbolChars();
    
    return available;
}

char PasswordGenerator::getRandomChar(const std::string& charset) {
    if (charset.empty()) return '\0';
    
    std::uniform_int_distribution<size_t> dist(0, charset.length() - 1);
    return charset[dist(rng)];
}

std::string PasswordGenerator::getRandomWord() {
    if (word_list.empty()) return "password";
    
    std::uniform_int_distribution<size_t> dist(0, word_list.size() - 1);
    return word_list[dist(rng)];
}
