#ifndef ARGPARSE_H
#define ARGPARSE_H

#include <string>
#include <vector>
#include <map>
#include <functional>
#include "password_generator.h"
#include "password_exporter.h"

struct Argument {
    std::string short_name;
    std::string long_name;
    std::string description;
    bool is_flag;
    bool required;
    std::string default_value;
    std::string value;
    std::function<void(const std::string&)> action;
};

struct ParsedArgs {
    GenerationMode mode = GenerationMode::RANDOM;
    PasswordConfig config;
    int batch_count = 1;
    bool interactive = false;
    bool show_help = false;
    bool show_version = false;
    bool evaluate_only = false;
    std::string password_to_evaluate;
    
    std::string output_file;
    ExportFormat export_format = ExportFormat::TXT;
    EncryptionType encryption = EncryptionType::NONE;
    std::string xor_key;
};

class ArgumentParser {
public:
    ArgumentParser(const std::string& program_name, const std::string& version);
    
    void addArgument(const std::string& short_name,
                     const std::string& long_name,
                     const std::string& description,
                     bool is_flag = false,
                     bool required = false,
                     const std::string& default_value = "",
                     std::function<void(const std::string&)> action = nullptr);
    
    ParsedArgs parse(int argc, char* argv[]);
    
    void showHelp() const;
    void showVersion() const;
    void showExamples() const;

private:
    std::string program_name;
    std::string version;
    std::vector<Argument> arguments;
    std::map<std::string, size_t> argument_map;
    
    void initializeArguments();
    std::string trim(const std::string& s);
};

#endif // ARGPARSE_H
