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

bool Rc4Cipher::process_buffer(std::vector<uint8_t>& buffer, const std::string& key, bool is_encrypt) {
    if (!isValidKeyLength(key.size())) {
        return false;
    }

    std::vector<uint8_t> byte_key(key.begin(), key.end());
    std::vector<uint8_t> iv(IV_SIZE);
    std::vector<uint8_t> data_to_process;

    if (is_encrypt) {
        std::random_device rd;
        for (auto& b : iv) {
            b = static_cast<uint8_t>(rd() % 256);
        }
        data_to_process = buffer;
    } else {
        if (buffer.size() < IV_SIZE) {
            return false;
        }
        std::copy(buffer.begin(), buffer.begin() + IV_SIZE, iv.begin());
        data_to_process.assign(buffer.begin() + IV_SIZE, buffer.end());
    }

    std::vector<uint8_t> s_box;
    ksa_init(byte_key, iv, s_box);

    std::vector<uint8_t> crypto_result;
    crypto_result.reserve(data_to_process.size());

    size_t i = 0;
    size_t j = 0;
    for (size_t k = 0; k < data_to_process.size(); ++k) {
        i = (i + 1) % SBOX_SIZE;
        j = (j + s_box[i]) % SBOX_SIZE;
        std::swap(s_box[i], s_box[j]);

        uint8_t keystream_byte = s_box[(s_box[i] + s_box[j]) % SBOX_SIZE];
        crypto_result.push_back(data_to_process[k] ^ keystream_byte);
    }

    buffer.clear();
    if (is_encrypt) {
        buffer.reserve(IV_SIZE + crypto_result.size());
        buffer.insert(buffer.end(), iv.begin(), iv.end());
    }
    buffer.insert(buffer.end(), crypto_result.begin(), crypto_result.end());

    return true;
}

std::string Rc4Cipher::encryptText(const std::string& text, const std::string& key) {
    std::vector<uint8_t> buffer(text.begin(), text.end());
    if (!process_buffer(buffer, key, true)) {
        return "";
    }
    return std::string(buffer.begin(), buffer.end());
}

std::string Rc4Cipher::decryptText(const std::string& text, const std::string& key) {
    std::vector<uint8_t> buffer(text.begin(), text.end());
    if (!process_buffer(buffer, key, false)) {
        return "";
    }
    return std::string(buffer.begin(), buffer.end());
}

bool Rc4Cipher::encryptFile(const std::string& inPath, const std::string& outPath, const std::string& key) {
    std::ifstream in_file(inPath, std::ios::binary);
    if (!in_file) {
        return false;
    }

    std::vector<uint8_t> buffer(
        (std::istreambuf_iterator<char>(in_file)),
        std::istreambuf_iterator<char>());
    in_file.close();

    if (!process_buffer(buffer, key, true)) {
        return false;
    }

    std::ofstream out_file(outPath, std::ios::binary);
    if (!out_file) {
        return false;
    }
    out_file.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
    return true;
}

bool Rc4Cipher::decryptFile(const std::string& inPath, const std::string& outPath, const std::string& key) {
    std::ifstream in_file(inPath, std::ios::binary);
    if (!in_file) {
        return false;
    }

    std::vector<uint8_t> buffer(
        (std::istreambuf_iterator<char>(in_file)),
        std::istreambuf_iterator<char>());
    in_file.close();

    if (!process_buffer(buffer, key, false)) {
        return false;
    }

    std::ofstream out_file(outPath, std::ios::binary);
    if (!out_file) {
        return false;
    }
    out_file.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
    return true;
}
