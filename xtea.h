#ifndef XTEA_H
#define XTEA_H

#include <vector>
#include <cstdint>

class Xtea {
private:
    const unsigned int numRounds = 32; 
    
    const uint32_t deltaConstant = 0x9E3779B9;  
    
    uint32_t keyWords[4];                      

public:

    Xtea(const std::vector<uint8_t>& keyBytes);

    void encryptBlock(const uint8_t* plaintext, uint8_t* ciphertext);

    void decryptBlock(const uint8_t* ciphertext, uint8_t* plaintext);
};

#endif // XTEA_H
