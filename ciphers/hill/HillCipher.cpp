#include "HillCipher.h"
#include <fstream>
#include <algorithm>

std::string HillCipher::getName() const {
    return "Hill (2x2)";
}

std::string HillCipher::getKeyRequirementsInfo() const {
    return "Key must be exactly 4 characters long, and its matrix must be invertible mod 256 (determinant must be odd).";
}

bool HillCipher::isValidKeyLength(size_t length) const {
    return length == BLOCK_SIZE * BLOCK_SIZE;
}
int HillCipher::calculate_determinant(const std::vector<uint8_t>& key_matrix) {
    int det = (static_cast<int>(key_matrix[0]) * key_matrix[3]) - 
              (static_cast<int>(key_matrix[1]) * key_matrix[2]);
    return (det % 256 + 256) % 256;
}
int HillCipher::find_modular_inverse(int a, int m) {
    a = (a % m + m) % m;
    for (int x = 1; x < m; x += 2) {
        if ((a * x) % m == 1) {
            return x;
        }
    }
    return -1;
}
bool HillCipher::invert_matrix(const std::vector<uint8_t>& key_matrix, std::vector<uint8_t>& inv_matrix) {
    int det = calculate_determinant(key_matrix);
    int inv_det = find_modular_inverse(det, 256);
    
    if (inv_det == -1) {
        return false;
    }

    inv_matrix.resize(4);
    // По формуле: [d, -b, -c, a] * inv_det mod 256
    int a = key_matrix[0];
    int b = key_matrix[1];
    int c = key_matrix[2];
    int d = key_matrix[3];

    inv_matrix[0] = static_cast<uint8_t>((d * inv_det) % 256);
    inv_matrix[1] = static_cast<uint8_t>(((256 - b) * inv_det) % 256);
    inv_matrix[2] = static_cast<uint8_t>(((256 - c) * inv_det) % 256);
    inv_matrix[3] = static_cast<uint8_t>((a * inv_det) % 256);

    return true;
}

bool HillCipher::process_buffer(std::vector<uint8_t>& buffer, const std::string& key, bool is_encrypt) {
    if (!isValidKeyLength(key.size())) {
        return false;
    }
    std::vector<uint8_t> key_matrix(key.begin(), key.end());
    std::vector<uint8_t> active_matrix;

    if (is_encrypt) {
        int det = calculate_determinant(key_matrix);
        if (find_modular_inverse(det, 256) == -1) {
            return false;
        }
        active_matrix = key_matrix;
        size_t padding_len = BLOCK_SIZE - (buffer.size() % BLOCK_SIZE);
        for (size_t i = 0; i < padding_len; ++i) {
            buffer.push_back(static_cast<uint8_t>(padding_len));
        }
    } else {
        if (!invert_matrix(key_matrix, active_matrix)) {
            return false; 
        }
        if (buffer.size() % BLOCK_SIZE != 0 || buffer.empty()) {
            return false;
        }
    }
    for (size_t i = 0; i < buffer.size(); i += BLOCK_SIZE) {
        uint8_t x1 = buffer[i];
        uint8_t x2 = buffer[i + 1];

        buffer[i]     = static_cast<uint8_t>((active_matrix[0] * x1 + active_matrix[1] * x2) % 256);
        buffer[i + 1] = static_cast<uint8_t>((active_matrix[2] * x1 + active_matrix[3] * x2) % 256);
    }
    if (!is_encrypt) {
        uint8_t padding_len = buffer.back();
        if (padding_len < 1 || padding_len > BLOCK_SIZE || padding_len > buffer.size()) {
            return false;
        }
        for (size_t i = buffer.size() - padding_len; i < buffer.size(); ++i) {
            if (buffer[i] != padding_len) return false;
        }
        buffer.resize(buffer.size() - padding_len);
    }

    return true;
}

std::string HillCipher::encryptText(const std::string& text, const std::string& key) {
    std::vector<uint8_t> buffer(text.begin(), text.end());
    if (!process_buffer(buffer, key, true)) return "";
    return std::string(buffer.begin(), buffer.end());
}

std::string HillCipher::decryptText(const std::string& text, const std::string& key) {
    std::vector<uint8_t> buffer(text.begin(), text.end());
    if (!process_buffer(buffer, key, false)) return "";
    return std::string(buffer.begin(), buffer.end());
}

bool HillCipher::encryptFile(const std::string& inPath, const std::string& outPath, const std::string& key) {
    std::ifstream in_file(inPath, std::ios::binary);
    if (!in_file) return false;

    std::vector<uint8_t> buffer(
        (std::istreambuf_iterator<char>(in_file)),
        std::istreambuf_iterator<char>());
    in_file.close();

    if (!process_buffer(buffer, key, true)) return false;

    std::ofstream out_file(outPath, std::ios::binary);
    if (!out_file) return false;
    out_file.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
    return true;
}

bool HillCipher::decryptFile(const std::string& inPath, const std::string& outPath, const std::string& key) {
    std::ifstream in_file(inPath, std::ios::binary);
    if (!in_file) return false;

    std::vector<uint8_t> buffer(
        (std::istreambuf_iterator<char>(in_file)),
        std::istreambuf_iterator<char>());
    in_file.close();

    if (!process_buffer(buffer, key, false)) return false;

    std::ofstream out_file(outPath, std::ios::binary);
    if (!out_file) return false;
    out_file.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
    return true;
}
