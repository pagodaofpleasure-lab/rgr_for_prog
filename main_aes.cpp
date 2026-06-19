#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include "aes.h"

void print_help() {
    std::cout << "AES-128 File Encryptor/Decryptor\n";
    std::cout << "Usage: \n1. Place 'input' file in the directory.\n";
    std::cout << "2. Enter 16-character key.\n";
    std::cout << "3. Choose mode: (e)ncrypt or (d)ecrypt.\n";
    std::cout << "Output will be saved to 'output'.\n\n";
}

int main() {
    print_help();

    std::string key_str, mode;
    std::cout << "Key (16 chars): ";
    std::cin >> key_str;
    if (key_str.length() != 16) {
        std::cerr << "Key must be 16 characters!\n";
        return 1;
    }

    std::cout << "Mode (e/d): ";
    std::cin >> mode;

    std::ifstream in("input", std::ios::binary);
    std::ofstream out("output", std::ios::binary);
    if (!in || !out) {
        std::cerr << "File error!\n";
        return 1;
    }

    std::vector<uint8_t> key(key_str.begin(), key_str.end());
    AES aes(key);

    const int64_t buffer_size = 1024 * 64; // 64KB buffer
    std::vector<uint8_t> buffer(buffer_size);
    uint8_t block_in[16], block_out[16];

    if (mode == "e") {
        while (in.read(reinterpret_cast<char*>(buffer.data()), buffer_size) || in.gcount() > 0) {
            int64_t bytes_read = in.gcount();
            int64_t i = 0;
            for (; i + 16 <= bytes_read; i += 16) {
                aes.encrypt(buffer.data() + i, block_out);
                out.write(reinterpret_cast<char*>(block_out), 16);
            }
            if (in.eof()) { // Padding PKCS#7
                uint8_t padding_val = 16 - (bytes_read - i);
                std::vector<uint8_t> last_block(16, padding_val);
                for (int64_t j = 0; j < (bytes_read - i); ++j) last_block[j] = buffer[i + j];
                aes.encrypt(last_block.data(), block_out);
                out.write(reinterpret_cast<char*>(block_out), 16);
            }
        }
    } else {
        in.seekg(0, std::ios::end);
        int64_t total_size = in.tellg();
        in.seekg(0, std::ios::beg);

        int64_t processed = 0;
        while (in.read(reinterpret_cast<char*>(buffer.data()), buffer_size) || in.gcount() > 0) {
            int64_t bytes_read = in.gcount();
            for (int64_t i = 0; i < bytes_read; i += 16) {
                aes.decrypt(buffer.data() + i, block_out);
                processed += 16;
                if (processed == total_size) { // Remove padding
                    uint8_t pad_len = block_out[15];
                    if (pad_len <= 16) out.write(reinterpret_cast<char*>(block_out), 16 - pad_len);
                } else {
                    out.write(reinterpret_cast<char*>(block_out), 16);
                }
            }
        }
    }

    in.close();
    out.close();
    std::cout << "Done.\n";
    return 0;
}
