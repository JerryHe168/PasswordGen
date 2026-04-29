#ifndef PASSWORD_GENERATOR_H
#define PASSWORD_GENERATOR_H

#include <string>
#include <vector>
#include <random>

enum class PasswordStrength {
    WEAK,
    MEDIUM,
    STRONG,
    VERY_STRONG
};

enum class GenerationMode {
    RANDOM,
    MEMORABLE,
    PATTERN
};

struct PasswordConfig {
    int length = 12;
    bool use_uppercase = true;
    bool use_lowercase = true;
    bool use_numbers = true;
    bool use_symbols = true;
    std::string pattern;
    int memorable_words = 2;
    int memorable_numbers = 2;
    int memorable_symbols = 1;
    std::string word_list_path;
};

struct GeneratedPassword {
    std::string password;
    PasswordStrength strength;
    std::string strength_description;
    int entropy;
};

void secureClear(std::string& str);

class PasswordGenerator {
public:
    PasswordGenerator();
    
    GeneratedPassword generate(const PasswordConfig& config, GenerationMode mode = GenerationMode::RANDOM);
    std::vector<GeneratedPassword> generateBatch(int count, const PasswordConfig& config, GenerationMode mode = GenerationMode::RANDOM);
    
    PasswordStrength evaluateStrength(const std::string& password);
    int calculateEntropy(const std::string& password);
    std::string strengthToString(PasswordStrength strength);
    std::string strengthToDescription(PasswordStrength strength);
    
    bool loadWordList(const std::string& filepath);
    size_t getWordCount() const { return word_list.size(); }
    void resetWordList() { word_list.clear(); initializeWordList(); }

private:
    std::mt19937 rng;
    
    std::string generateRandom(const PasswordConfig& config);
    std::string generateMemorable(const PasswordConfig& config);
    std::string generatePattern(const PasswordConfig& config);
    
    std::string getUppercaseChars() const;
    std::string getLowercaseChars() const;
    std::string getNumberChars() const;
    std::string getSymbolChars() const;
    std::string getAvailableChars(const PasswordConfig& config) const;
    
    char getRandomChar(const std::string& charset);
    std::string getRandomWord();
    void initializeWordList();
    void ensureWordListLoaded(const PasswordConfig& config);
    
    std::vector<std::string> word_list;
    std::string current_word_list_path;
};

#endif // PASSWORD_GENERATOR_H
