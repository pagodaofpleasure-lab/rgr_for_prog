#pragma once

#include "ICipher.h"

namespace speck {

class SpeckCipher : public ICipher {
public:
    std::string getName() const override;
    std::string getKeyRequirementsInfo() const override;
    bool isValidKeyLength(size_t length) const override;

    std::string encryptText(const std::string& text, const std::string& key) override;
    std::string decryptText(const std::string& text, const std::string& key) override;

    bool encryptFile(const std::string& inPath, const std::string& outPath, const std::string& key) override;
    bool decryptFile(const std::string& inPath, const std::string& outPath, const std::string& key) override;
};

} // namespace speck
