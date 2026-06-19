#pragma once

#include <cstdint>

namespace des {

const int kBlockSize = 8;
const int kKeySize = 8;

void encryptBlock(const unsigned char plaintext[kBlockSize], unsigned char ciphertext[kBlockSize], const unsigned char key[kKeySize]);
void decryptBlock(const unsigned char ciphertext[kBlockSize], unsigned char plaintext[kBlockSize], const unsigned char key[kKeySize]);

} // namespace des
