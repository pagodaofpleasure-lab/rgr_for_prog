#include "Rc4Cipher.h"
#include <fstream>
#include <random>
#include <algorithm>

const size_t SBOX_SIZE = 256;
const size_t IV_SIZE = 16;

std::string Rc4Cipher::getName() const {
    return "RC4";
}

std::string Rc4Cipher::getKeyRequirementsInfo() const {
    return "Key length must be between 1 and 256 bytes (recommended 16+ bytes).";
}

bool Rc4Cipher::isValidKeyLength(size_t length) const {
    return length >= 1 && length <= 256;
}

void Rc4Cipher::ksa_init(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, std::vector<uint8_t>& s_box) {
    s_box.resize(SBOX_SIZE);
    for (size_t i = 0; i < SBOX_SIZE; ++i) {
        s_box[i] = static_cast<uint8_t>(i);
    }

    std::vector<uint8_t> full_key = key;
    full_key.insert(full_key.end(), iv.begin(), iv.end());

    size_t j = 0;
    for (size_t i = 0; i < SBOX_SIZE; ++i) {
        j = (j + s_box[i] + full_key[i % full_key.size()]) % SBOX_SIZE;
        std::swap(s_box[i], s_box[j]);
    }
}

std::vector<uint8_t> Rc4Cipher::run_rc4(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv) {
    std::vector<uint8_t> s_box;
    ksa_init(key, iv, s_box);

    std::vector<uint8_t> result;
    result.reserve(data.size());

    size_t i = 0;
    size_t j = 0;

    for (size_t k = 0; k < data.size(); ++k) {
        i = (i + 1) % SBOX_SIZE;
        j = (j + s_box[i]) % SBOX_SIZE;
        std::swap(s_box[i], s_box[j]);
        
        uint8_t keystream_byte = s_box[(s_box[i] + s_box[j]) % SBOX_SIZE];
        result.push_back(data[k] ^ keystream_byte);
    }
    return result;
}

std::string Rc4Cipher::encryptText(const std::string& text, const std::string& key) {
    std::vector<uint8_t> byte_key(key.begin(), key.end());
    std::vector<uint8_t> byte_data(text.begin(), text.end());

    std::random_device rd;
    std::vector<uint8_t> iv(IV_SIZE);
    for (auto& b : iv) b = static_cast<uint8_t>(rd() % 256);

    std::vector<uint8_t> ciphertext = run_rc4(byte_data, byte_key, iv);

    std::string result;
    result.reserve(IV_SIZE + ciphertext.size());
    result.assign(iv.begin(), iv.end());
    result.append(ciphertext.begin(), ciphertext.end());
    return result;
}

std::string Rc4Cipher::decryptText(const std::string& text, const std::string& key) {
    if (text.size() < IV_SIZE) return "";

    std::vector<uint8_t> byte_key(key.begin(), key.end());
    std::vector<uint8_t> iv(text.begin(), text.begin() + IV_SIZE);
    std::vector<uint8_t> ciphertext(text.begin() + IV_SIZE, text.end());

    std::vector<uint8_t> decrypted = run_rc4(ciphertext, byte_key, iv);
    return std::string(decrypted.begin(), decrypted.end());
}

bool Rc4Cipher::encryptFile(const std::string& inPath, const std::string& outPath, const std::string& key) {
    std::ifstream in_file(inPath, std::ios::binary);
    if (!in_file) return false;

    std::ofstream out_file(outPath, std::ios::binary);
    if (!out_file) return false;

    std::vector<uint8_t> byte_key(key.begin(), key.end());
    std::random_device rd;
    std::vector<uint8_t> iv(IV_SIZE);
    for (auto& b : iv) b = static_cast<uint8_t>(rd() % 256);

    out_file.write(reinterpret_cast<const char*>(iv.data()), IV_SIZE);

    std::vector<uint8_t> buffer((std::istreambuf_iterator<char>(in_file)), std::istreambuf_iterator<char>());
    std::vector<uint8_t> ciphertext = run_rc4(buffer, byte_key, iv);

    out_file.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
    return true;
}

bool Rc4Cipher::decryptFile(const std::string& inPath, const std::string& outPath, const std::string& key) {
    std::ifstream in_file(inPath, std::ios::binary);
    if (!in_file) return false;

    std::ofstream out_file(outPath, std::ios::binary);
    if (!out_file) return false;

    std::vector<uint8_t> iv(IV_SIZE);
    in_file.read(reinterpret_cast<char*>(iv.data()), IV_SIZE);
    if (in_file.gcount() < static_cast<std::streamsize>(IV_SIZE)) return false;

    std::vector<uint8_t> byte_key(key.begin(), key.end());
    std::vector<uint8_t> buffer((std::istreambuf_iterator<char>(in_file)), std::istreambuf_iterator<char>());
    std::vector<uint8_t> decrypted = run_rc4(buffer, byte_key, iv);

    out_file.write(reinterpret_cast<const char*>(decrypted.data()), decrypted.size());
    return true;
}
