#ifndef PASSWORD_EXPORTER_H
#define PASSWORD_EXPORTER_H

#include <string>
#include <vector>
#include "password_generator.h"

enum class ExportFormat {
    TXT,
    CSV,
    JSON
};

enum class EncryptionType {
    NONE,
    XOR,
    BASE64
};

class PasswordExporter {
public:
    static bool exportToFile(const std::string& filename, 
                              const std::vector<GeneratedPassword>& passwords,
                              ExportFormat format = ExportFormat::TXT,
                              EncryptionType encryption = EncryptionType::NONE,
                              const std::string& xor_key = "");
    
    static std::string exportToString(const std::vector<GeneratedPassword>& passwords,
                                        ExportFormat format = ExportFormat::TXT,
                                        EncryptionType encryption = EncryptionType::NONE,
                                        const std::string& xor_key = "");

private:
    static std::string toTXT(const std::vector<GeneratedPassword>& passwords);
    static std::string toCSV(const std::vector<GeneratedPassword>& passwords);
    static std::string toJSON(const std::vector<GeneratedPassword>& passwords);
    
    static std::string xorEncrypt(const std::string& data, const std::string& key);
    static std::string base64Encode(const std::string& data);
    static std::string base64Decode(const std::string& data);
    
    static const std::string base64_chars;
};

#endif // PASSWORD_EXPORTER_H
