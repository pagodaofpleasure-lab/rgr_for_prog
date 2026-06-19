#ifndef RC5_H
#define RC5_H

#include <vector>
#include <string>
#include <cstdint>

class RC5 {
private:
    static const int wordSize = 32;      
    static const int roundCount = 12;    
    static const int keyLengthBytes = 16;
    static const int tableSize = 26;      

    static const uint32_t constantP = 0xB7E15163;
    static const uint32_t constantQ = 0x9E3779B9;

    uint32_t secretTable[tableSize]; // Таблица ключей S

    uint32_t leftRotate(uint32_t value, uint32_t shift);
    uint32_t rightRotate(uint32_t value, uint32_t shift);

public:
    // Иницилизация таблицы ключей
    RC5(const std::vector<uint8_t>& secretKey);

    // Функции  8-байтового блока 
    void encryptBlock(uint32_t& leftWord, uint32_t& rightWord);
    void decryptBlock(uint32_t& leftWord, uint32_t& rightWord);
};

// Функции для работы с файлами и текстом
void padBuffer(std::vector<uint8_t>& buffer);
bool unpadBuffer(std::vector<uint8_t>& buffer);

std::vector<uint8_t> encryptCbc(RC5& cipher, const std::vector<uint8_t>& plainTextBytes, const std::vector<uint8_t>& initVector);
std::vector<uint8_t> decryptCbc(RC5& cipher, const std::vector<uint8_t>& cipherTextBytes, const std::vector<uint8_t>& initVector);

bool encryptFile(RC5& cipher, const std::string& inputPath, const std::string& outputPath, const std::vector<uint8_t>& initVector);
bool decryptFile(RC5& cipher, const std::string& inputPath, const std::string& outputPath, const std::vector<uint8_t>& initVector);

#endif 
