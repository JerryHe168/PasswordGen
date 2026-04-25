#include "../include/password_generator.h"
#include <algorithm>
#include <cctype>
#include <cmath>
#include <chrono>
#include <unordered_set>

PasswordGenerator::PasswordGenerator() {
    auto seed = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    rng.seed(static_cast<unsigned int>(seed));
    initializeWordList();
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
}

GeneratedPassword PasswordGenerator::generate(const PasswordConfig& config, GenerationMode mode) {
    GeneratedPassword result;
    
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
    
    if (enabled_types > config.length) {
        std::string password;
        password.reserve(config.length);
        
        for (int i = 0; i < config.length; ++i) {
            password += getRandomChar(available);
        }
        
        std::shuffle(password.begin(), password.end(), rng);
        return password;
    }
    
    std::string password;
    password.reserve(config.length);
    
    if (config.use_uppercase) {
        password += getRandomChar(getUppercaseChars());
    }
    if (config.use_lowercase) {
        password += getRandomChar(getLowercaseChars());
    }
    if (config.use_numbers) {
        password += getRandomChar(getNumberChars());
    }
    if (config.use_symbols) {
        password += getRandomChar(getSymbolChars());
    }
    
    while (password.length() < static_cast<size_t>(config.length)) {
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
