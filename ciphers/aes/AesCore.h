#pragma once

namespace aes {

const int kBlockSize = 16;
const int kKeySize = 16;

class AesCore {
public:
    explicit AesCore(const unsigned char key[kKeySize]);

    void encryptBlock(const unsigned char input[kBlockSize], unsigned char output[kBlockSize]);
    void decryptBlock(const unsigned char input[kBlockSize], unsigned char output[kBlockSize]);

private:
    unsigned char roundKeys[176];
    static const unsigned char sbox[256];
    static const unsigned char rsbox[256];

    void keyExpansion(const unsigned char key[kKeySize]);
    void subBytes(unsigned char state[kBlockSize]);
    void invSubBytes(unsigned char state[kBlockSize]);
    void shiftRows(unsigned char state[kBlockSize]);
    void invShiftRows(unsigned char state[kBlockSize]);
    void mixColumns(unsigned char state[kBlockSize]);
    void invMixColumns(unsigned char state[kBlockSize]);
    void addRoundKey(unsigned char state[kBlockSize], const unsigned char* key);
};

} // namespace aes
