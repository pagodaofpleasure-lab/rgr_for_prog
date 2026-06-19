#pragma once
#include <string>

class ICipher {
public:
    virtual ~ICipher() = default;

    virtual std::string getName() const = 0;
    virtual std::string getKeyRequirementsInfo() const = 0;
    virtual bool isValidKeyLength(size_t length) const = 0;

    virtual std::string encryptText(const std::string& text, const std::string& key) = 0;
    virtual std::string decryptText(const std::string& text, const std::string& key) = 0;

    virtual bool encryptFile(const std::string& inPath, const std::string& outPath, const std::string& key) = 0;
    virtual bool decryptFile(const std::string& inPath, const std::string& outPath, const std::string& key) = 0;
};
