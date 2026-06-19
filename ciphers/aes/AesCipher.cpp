#include "AesCipher.h"

#include "AesCore.h"
#include "utils/HexCodec.h"

#include <fstream>
#include <iterator>
#include <vector>

namespace aes {

static bool processBuffer(std::vector<unsigned char>& buffer, const std::string& key, bool encrypt) {
    unsigned char keyBytes[kKeySize];
    for (int i = 0; i < kKeySize; ++i) {
        keyBytes[i] = (unsigned char)key[i];
    }

    AesCore core(keyBytes);
    unsigned char block[kBlockSize];
    unsigned char outBlock[kBlockSize];

    if (encrypt) {
        addPadding(buffer, kBlockSize);
    } else if (buffer.empty() || buffer.size() % kBlockSize != 0) {
        return false;
    }

    for (size_t i = 0; i < buffer.size(); i += kBlockSize) {
        for (int j = 0; j < kBlockSize; ++j) {
            block[j] = buffer[i + j];
        }

        if (encrypt) {
            core.encryptBlock(block, outBlock);
        } else {
            core.decryptBlock(block, outBlock);
        }

        for (int j = 0; j < kBlockSize; ++j) {
            buffer[i + j] = outBlock[j];
        }
    }

    if (encrypt) {
        return true;
    }

    return removePadding(buffer, kBlockSize);
}

std::string AesCipher::getName() const {
    return "AES-128";
}

std::string AesCipher::getKeyRequirementsInfo() const {
    return "ровно 16 символов";
}

bool AesCipher::isValidKeyLength(size_t length) const {
    return length == kKeySize;
}

std::string AesCipher::encryptText(const std::string& text, const std::string& key) {
    std::vector<unsigned char> buffer(text.begin(), text.end());
    if (!processBuffer(buffer, key, true)) {
        return "[!] Ошибка шифрования";
    }
    return bytesToHex(buffer);
}

std::string AesCipher::decryptText(const std::string& text, const std::string& key) {
    std::vector<unsigned char> buffer = hexToBytes(text);
    if (buffer.empty()) {
        return "[!] Ошибка: неверный формат hex";
    }
    if (!processBuffer(buffer, key, false)) {
        return "[!] Ошибка: неверный пароль или повреждённые данные";
    }
    return std::string(buffer.begin(), buffer.end());
}

bool AesCipher::encryptFile(const std::string& inPath, const std::string& outPath, const std::string& key) {
    std::ifstream inFile(inPath, std::ios::binary);
    if (!inFile) {
        return false;
    }

    std::vector<unsigned char> buffer(
        (std::istreambuf_iterator<char>(inFile)),
        std::istreambuf_iterator<char>());
    inFile.close();

    if (!processBuffer(buffer, key, true)) {
        return false;
    }

    std::ofstream outFile(outPath, std::ios::binary);
    if (!outFile) {
        return false;
    }
    outFile.write((const char*)buffer.data(), buffer.size());
    return true;
}

bool AesCipher::decryptFile(const std::string& inPath, const std::string& outPath, const std::string& key) {
    std::ifstream inFile(inPath, std::ios::binary);
    if (!inFile) {
        return false;
    }

    std::vector<unsigned char> buffer(
        (std::istreambuf_iterator<char>(inFile)),
        std::istreambuf_iterator<char>());
    inFile.close();

    if (!processBuffer(buffer, key, false)) {
        return false;
    }

    std::ofstream outFile(outPath, std::ios::binary);
    if (!outFile) {
        return false;
    }
    outFile.write((const char*)buffer.data(), buffer.size());
    return true;
}

} // namespace aes
