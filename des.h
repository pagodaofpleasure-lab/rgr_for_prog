#ifndef DES_H
#define DES_H

#include <cstdint>
#include <vector>

class DES {
public:
    DES(uint64_t key);
    uint64_t encrypt(uint64_t block);
    uint64_t decrypt(uint64_t block);

private:
    uint64_t subkeys[16];
    void generateSubkeys(uint64_t key);
    uint64_t permute(uint64_t val, const uint8_t* table, int n);
    uint32_t f(uint32_t R, uint64_t k);

    static const uint8_t IP[];
    static const uint8_t FP[];
    static const uint8_t E[];
    static const uint8_t P[];
    static const uint8_t S[8][64];
    static const uint8_t PC1[];
    static const uint8_t PC2[];
    static const uint8_t shifts[];
};

#endif
