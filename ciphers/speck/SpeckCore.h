#pragma once

#include <cstdint>

namespace speck {

const int kBlockSize = 16;
const int kKeySize = 16;
const int kRounds = 32;

void encryptBlock(const unsigned char* plaintext, unsigned char* ciphertext, const unsigned char* key);
void decryptBlock(const unsigned char* ciphertext, unsigned char* plaintext, const unsigned char* key);

} // namespace speck
