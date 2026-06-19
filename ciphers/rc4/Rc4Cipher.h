#pragma once

#include "ICipher.h"

namespace rc4 {

class Rc4Cipher : public ICipher {
public:
    std::string getName() const override;
    std::string getKeyRequirementsInfo() const override;
    bool isValidKeyLength(size_t length) const override;

    std::string encryptText(const std::string& text, const std::string& key) override;
    std::string decryptText(const std::string& text, const std::string& key) override;

    bool encryptFile(const std::string& inPath, const std::string& outPath, const std::string& key) override;
    bool decryptFile(const std::string& inPath, const std::string& outPath, const std::string& key) override;
};

} // namespace rc4
