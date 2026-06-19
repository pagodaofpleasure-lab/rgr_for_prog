#include "Rc4Cipher.h"

#include "Rc4Core.h"
#include "utils/HexCodec.h"

#include <fstream>
#include <iterator>
#include <random>
#include <vector>

namespace rc4 {

static std::vector<unsigned char> makeKeyBytes(const std::string& key) {
    return std::vector<unsigned char>(key.begin(), key.end());
}

static std::vector<unsigned char> generateIv() {
    std::random_device rd;
    std::vector<unsigned char> iv(kIvSize);
    for (auto& b : iv) {
        b = (unsigned char)(rd() % 256);
    }
    return iv;
}

std::string Rc4Cipher::getName() const {
    return "RC4";
}

std::string Rc4Cipher::getKeyRequirementsInfo() const {
    return "от 1 до 256 символов";
}

bool Rc4Cipher::isValidKeyLength(size_t length) const {
    return length >= 1 && length <= kMaxKeySize;
}

std::string Rc4Cipher::encryptText(const std::string& text, const std::string& key) {
    std::vector<unsigned char> byteKey = makeKeyBytes(key);
    std::vector<unsigned char> byteData(text.begin(), text.end());
    std::vector<unsigned char> iv = generateIv();

    std::vector<unsigned char> ciphertext = crypt(byteData, byteKey, iv);
    std::vector<unsigned char> result;
    result.reserve(iv.size() + ciphertext.size());
    result.insert(result.end(), iv.begin(), iv.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());

    return bytesToHex(result);
}

std::string Rc4Cipher::decryptText(const std::string& text, const std::string& key) {
    std::vector<unsigned char> buffer = hexToBytes(text);
    if (buffer.size() < (size_t)kIvSize) {
        return "[!] Ошибка: неверный формат hex";
    }

    std::vector<unsigned char> byteKey = makeKeyBytes(key);
    std::vector<unsigned char> iv(buffer.begin(), buffer.begin() + kIvSize);
    std::vector<unsigned char> ciphertext(buffer.begin() + kIvSize, buffer.end());

    std::vector<unsigned char> decrypted = crypt(ciphertext, byteKey, iv);
    return std::string(decrypted.begin(), decrypted.end());
}

bool Rc4Cipher::encryptFile(const std::string& inPath, const std::string& outPath, const std::string& key) {
    std::ifstream inFile(inPath, std::ios::binary);
    if (!inFile) {
        return false;
    }

    std::vector<unsigned char> buffer(
        (std::istreambuf_iterator<char>(inFile)),
        std::istreambuf_iterator<char>());
    inFile.close();

    std::vector<unsigned char> byteKey = makeKeyBytes(key);
    std::vector<unsigned char> iv = generateIv();
    std::vector<unsigned char> ciphertext = crypt(buffer, byteKey, iv);

    std::ofstream outFile(outPath, std::ios::binary);
    if (!outFile) {
        return false;
    }

    outFile.write((const char*)iv.data(), iv.size());
    outFile.write((const char*)ciphertext.data(), ciphertext.size());
    return true;
}

bool Rc4Cipher::decryptFile(const std::string& inPath, const std::string& outPath, const std::string& key) {
    std::ifstream inFile(inPath, std::ios::binary);
    if (!inFile) {
        return false;
    }

    std::vector<unsigned char> iv(kIvSize);
    inFile.read((char*)iv.data(), kIvSize);
    if (inFile.gcount() < kIvSize) {
        return false;
    }

    std::vector<unsigned char> buffer(
        (std::istreambuf_iterator<char>(inFile)),
        std::istreambuf_iterator<char>());
    inFile.close();

    std::vector<unsigned char> byteKey = makeKeyBytes(key);
    std::vector<unsigned char> decrypted = crypt(buffer, byteKey, iv);

    std::ofstream outFile(outPath, std::ios::binary);
    if (!outFile) {
        return false;
    }
    outFile.write((const char*)decrypted.data(), decrypted.size());
    return true;
}

} // namespace rc4
