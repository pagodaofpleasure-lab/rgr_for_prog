#include "SpeckCipher.h"

#include "SpeckCore.h"
#include "utils/HexCodec.h"

#include <fstream>
#include <iterator>
#include <vector>

namespace speck {

std::string SpeckCipher::getName() const {
    return "Speck 128/128";
}

std::string SpeckCipher::getKeyRequirementsInfo() const {
    return "ровно 16 символов";
}

bool SpeckCipher::isValidKeyLength(size_t length) const {
    return length == 16;
}

std::string SpeckCipher::encryptText(const std::string& text, const std::string& key) {
    std::vector<unsigned char> buffer(text.begin(), text.end());
    addPadding(buffer, kBlockSize);

    unsigned char block[kBlockSize];
    unsigned char outBlock[kBlockSize];

    for (size_t i = 0; i < buffer.size(); i += kBlockSize) {
        for (int j = 0; j < kBlockSize; j++) {
            block[j] = buffer[i + j];
        }
        encryptBlock(block, outBlock, (const unsigned char*)key.c_str());
        for (int j = 0; j < kBlockSize; j++) {
            buffer[i + j] = outBlock[j];
        }
    }

    return bytesToHex(buffer);
}

std::string SpeckCipher::decryptText(const std::string& text, const std::string& key) {
    std::vector<unsigned char> buffer = hexToBytes(text);
    if (buffer.empty() || buffer.size() % kBlockSize != 0) {
        return "Ошибка: неверный формат зашифрованного текста";
    }

    unsigned char block[kBlockSize];
    unsigned char outBlock[kBlockSize];

    for (size_t i = 0; i < buffer.size(); i += kBlockSize) {
        for (int j = 0; j < kBlockSize; j++) {
            block[j] = buffer[i + j];
        }
        decryptBlock(block, outBlock, (const unsigned char*)key.c_str());
        for (int j = 0; j < kBlockSize; j++) {
            buffer[i + j] = outBlock[j];
        }
    }

    if (!removePadding(buffer, kBlockSize)) {
        return "Ошибка: неверный пароль или повреждённые данные";
    }

    return std::string(buffer.begin(), buffer.end());
}

bool SpeckCipher::encryptFile(const std::string& inPath, const std::string& outPath, const std::string& key) {
    std::ifstream inFile(inPath, std::ios::binary);
    if (!inFile) {
        return false;
    }

    std::vector<unsigned char> buffer(
        (std::istreambuf_iterator<char>(inFile)),
        std::istreambuf_iterator<char>());
    inFile.close();

    addPadding(buffer, kBlockSize);

    unsigned char block[kBlockSize];
    unsigned char outBlock[kBlockSize];

    for (size_t i = 0; i < buffer.size(); i += kBlockSize) {
        for (int j = 0; j < kBlockSize; j++) {
            block[j] = buffer[i + j];
        }
        encryptBlock(block, outBlock, (const unsigned char*)key.c_str());
        for (int j = 0; j < kBlockSize; j++) {
            buffer[i + j] = outBlock[j];
        }
    }

    std::ofstream outFile(outPath, std::ios::binary);
    if (!outFile) {
        return false;
    }
    outFile.write((const char*)buffer.data(), buffer.size());
    return true;
}

bool SpeckCipher::decryptFile(const std::string& inPath, const std::string& outPath, const std::string& key) {
    std::ifstream inFile(inPath, std::ios::binary);
    if (!inFile) {
        return false;
    }

    std::vector<unsigned char> buffer(
        (std::istreambuf_iterator<char>(inFile)),
        std::istreambuf_iterator<char>());
    inFile.close();

    if (buffer.empty() || buffer.size() % kBlockSize != 0) {
        return false;
    }

    unsigned char block[kBlockSize];
    unsigned char outBlock[kBlockSize];

    for (size_t i = 0; i < buffer.size(); i += kBlockSize) {
        for (int j = 0; j < kBlockSize; j++) {
            block[j] = buffer[i + j];
        }
        decryptBlock(block, outBlock, (const unsigned char*)key.c_str());
        for (int j = 0; j < kBlockSize; j++) {
            buffer[i + j] = outBlock[j];
        }
    }

    if (!removePadding(buffer, kBlockSize)) {
        return false;
    }

    std::ofstream outFile(outPath, std::ios::binary);
    if (!outFile) {
        return false;
    }
    outFile.write((const char*)buffer.data(), buffer.size());
    return true;
}

} // namespace speck
