#pragma once
#include "../../include/ICipher.h"
#include <vector>
#include <cstdint>

class Rc4Cipher : public ICipher {
public:
    std::string getName() const override;
    std::string getKeyRequirementsInfo() const override;
    bool isValidKeyLength(size_t length) const override;

    std::string encryptText(const std::string& text, const std::string& key) override;
    std::string decryptText(const std::string& text, const std::string& key) override;

    bool encryptFile(const std::string& inPath, const std::string& outPath, const std::string& key) override;
    bool decryptFile(const std::string& inPath, const std::string& outPath, const std::string& key) override;

private:
    void ksa_init(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, std::vector<uint8_t>& s_box);
    std::vector<uint8_t> run_rc4(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv);
};
