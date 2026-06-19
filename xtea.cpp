#include "xtea.h"
#include <cstring>
#include <stdexcept>

using namespace std;

Xtea::Xtea(const vector<uint8_t>& keyBytes) {
    if (keyBytes.size() < 16) {
        throw invalid_argument("Длина ключа Xtea должна быть не менее 16 байт.");
    }
    
    // Побайтовое копирование в массив keyWords с использованием сдвига индексов
    memcpy(&keyWords[0], &keyBytes[0], sizeof(uint32_t));
    memcpy(&keyWords[1], &keyBytes[4], sizeof(uint32_t));
    memcpy(&keyWords[2], &keyBytes[8], sizeof(uint32_t));
    memcpy(&keyWords[3], &keyBytes[12], sizeof(uint32_t));
}

// Шифрование одного блока (8 байт)
void Xtea::encryptBlock(const uint8_t* plaintext, uint8_t* ciphertext) {
    uint32_t wordLeft, wordRight;
    
    memcpy(&wordLeft, plaintext, sizeof(uint32_t));
    memcpy(&wordRight, plaintext + sizeof(uint32_t), sizeof(uint32_t));

    uint32_t sumAccumulator = 0;
    
    for (unsigned int i = 0; i < numRounds; i++) {
        wordLeft += (((wordRight << 4) ^ (wordRight >> 5)) + wordRight) ^ (sumAccumulator + keyWords[sumAccumulator & 3]);
        sumAccumulator += deltaConstant;
        wordRight += (((wordLeft << 4) ^ (wordLeft >> 5)) + wordLeft) ^ (sumAccumulator + keyWords[(sumAccumulator >> 11) & 3]);
    }

    memcpy(ciphertext, &wordLeft, sizeof(uint32_t));
    memcpy(ciphertext + sizeof(uint32_t), &wordRight, sizeof(uint32_t));
}

// Расшифрование одного блока (8 байт)
void Xtea::decryptBlock(const uint8_t* ciphertext, uint8_t* plaintext) {
    uint32_t wordLeft, wordRight;
    
    memcpy(&wordLeft, ciphertext, sizeof(uint32_t));
    memcpy(&wordRight, ciphertext + sizeof(uint32_t), sizeof(uint32_t));

    uint32_t sumAccumulator = deltaConstant * numRounds;
    
    for (unsigned int i = 0; i < numRounds; i++) {
        wordRight -= (((wordLeft << 4) ^ (wordLeft >> 5)) + wordLeft) ^ (sumAccumulator + keyWords[(sumAccumulator >> 11) & 3]);
        sumAccumulator -= deltaConstant;
        wordLeft -= (((wordRight << 4) ^ (wordRight >> 5)) + wordRight) ^ (sumAccumulator + keyWords[sumAccumulator & 3]);
    }

    memcpy(plaintext, &wordLeft, sizeof(uint32_t));
    memcpy(plaintext + sizeof(uint32_t), &wordRight, sizeof(uint32_t));
}