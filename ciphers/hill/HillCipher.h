#pragma once
#include "../../include/ICipher.h"
#include <vector>
#include <cstdint>

class HillCipher : public ICipher {
public:
    std::string getName() const override;
    std::string getKeyRequirementsInfo() const override;
    bool isValidKeyLength(size_t length) const override;

    std::string encryptText(const std::string& text, const std::string& key) override;
    std::string decryptText(const std::string& text, const std::string& key) override;

    bool encryptFile(const std::string& inPath, const std::string& outPath, const std::string& key) override;
    bool decryptFile(const std::string& inPath, const std::string& outPath, const std::string& key) override;

private:
    static const size_t BLOCK_SIZE = 2;
    bool process_buffer(std::vector<uint8_t>& buffer, const std::string& key, bool is_encrypt);
    int calculate_determinant(const std::vector<uint8_t>& key_matrix);
    int find_modular_inverse(int a, int m);
    bool invert_matrix(const std::vector<uint8_t>& key_matrix, std::vector<uint8_t>& inv_matrix);
};
