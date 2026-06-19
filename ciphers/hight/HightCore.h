#pragma once

#include <vector>

namespace hight {

const int kBlockSize = 8;
const int kKeySize = 16;

class HightCore {
public:
    void makeRoundKeys(const unsigned char key[16], std::vector<unsigned char>& roundKeys);
    void encryptBlock(const std::vector<unsigned char>& roundKeys, unsigned char block[8]);
    void decryptBlock(const std::vector<unsigned char>& roundKeys, unsigned char block[8]);
};

} // namespace hight
