#include "HightCipher.h"

#include "HightCore.h"
#include "utils/HexCodec.h"

#include <fstream>
#include <iterator>
#include <vector>

namespace hight {

static std::vector<unsigned char> prepareKey(const std::string& key) {
    std::vector<unsigned char> result(16, 0);
    for (size_t i = 0; i < key.size() && i < 16; i++) {
        result[i] = (unsigned char)key[i];
    }
    return result;
}

static bool processBuffer(std::vector<unsigned char>& buffer, const std::string& key, bool encrypt) {
    HightCore core;
    std::vector<unsigned char> userKey = prepareKey(key);
    std::vector<unsigned char> roundKeys;
    core.makeRoundKeys(userKey.data(), roundKeys);

    unsigned char block[8];

    if (encrypt) {
        addPadding(buffer, kBlockSize);
    } else if (buffer.empty() || buffer.size() % kBlockSize != 0) {
        return false;
    }

    for (size_t i = 0; i < buffer.size(); i += kBlockSize) {
        for (int j = 0; j < kBlockSize; j++) {
            block[j] = buffer[i + j];
        }

        if (encrypt) {
            core.encryptBlock(roundKeys, block);
        } else {
            core.decryptBlock(roundKeys, block);
        }

        for (int j = 0; j < kBlockSize; j++) {
            buffer[i + j] = block[j];
        }
    }

    if (encrypt) {
        return true;
    }

    return removePadding(buffer, kBlockSize);
}

std::string HightCipher::getName() const {
    return "HIGHT";
}

std::string HightCipher::getKeyRequirementsInfo() const {
    return "от 1 до 16 символов";
}

bool HightCipher::isValidKeyLength(size_t length) const {
    return length >= 1 && length <= 16;
}

std::string HightCipher::encryptText(const std::string& text, const std::string& key) {
    std::vector<unsigned char> buffer(text.begin(), text.end());
    if (!processBuffer(buffer, key, true)) {
        return "[!] Ошибка шифрования";
    }
    return bytesToHex(buffer);
}

std::string HightCipher::decryptText(const std::string& text, const std::string& key) {
    std::vector<unsigned char> buffer = hexToBytes(text);
    if (buffer.empty()) {
        return "[!] Ошибка: неверный формат hex";
    }
    if (!processBuffer(buffer, key, false)) {
        return "[!] Ошибка: неверный пароль или повреждённые данные";
    }
    return std::string(buffer.begin(), buffer.end());
}

bool HightCipher::encryptFile(const std::string& inPath, const std::string& outPath, const std::string& key) {
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

bool HightCipher::decryptFile(const std::string& inPath, const std::string& outPath, const std::string& key) {
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

} // namespace hight
