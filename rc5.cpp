#include "rc5.h"
#include <stdexcept>

using namespace std;

uint32_t RC5::leftRotate(uint32_t value, uint32_t shift) {
    shift &= 31;
    return (value << shift) | (value >> (wordSize - shift));
}

uint32_t RC5::rightRotate(uint32_t value, uint32_t shift) {
    shift &= 31;
    return (value >> shift) | (value << (wordSize - shift));
}

// Расширение ключа (Key Expansion)
RC5::RC5(const vector<uint8_t>& secretKey) {
    if (secretKey.size() != keyLengthBytes) {
        throw invalid_argument("Ключ должен быть 16 байт");
    }

    int wordCount = keyLengthBytes / 4; 
    uint32_t keyWords[4] = {0};
    for (int i = 0; i < keyLengthBytes; i++) {
        keyWords[i / 4] |= (uint32_t)secretKey[i] << (8 * (i % 4));
    }

    secretTable[0] = constantP;
    for (int i = 1; i < tableSize; i++) {
        secretTable[i] = secretTable[i - 1] + constantQ;
    }

    uint32_t i = 0, j = 0;
    uint32_t accumulatedA = 0, accumulatedB = 0;
    int mixSteps = 3 * (tableSize > wordCount ? tableSize : wordCount);

    for (int k = 0; k < mixSteps; k++) {
        accumulatedA = secretTable[i] = leftRotate(secretTable[i] + accumulatedA + accumulatedB, 3);
        accumulatedB = keyWords[j] = leftRotate(keyWords[j] + accumulatedA + accumulatedB, (accumulatedA + accumulatedB));
        i = (i + 1) % tableSize;
        j = (j + 1) % wordCount;
    }
}

// Шифрование одного 8-байтового блока
void RC5::encryptBlock(uint32_t& leftWord, uint32_t& rightWord) {
    uint32_t valueA = leftWord + secretTable[0];
    uint32_t valueB = rightWord + secretTable[0];
    for (int i = 1; i <= roundCount; i++) {
        valueA = leftRotate(valueA ^ valueB, valueB) + secretTable[2 * i];
        valueB = leftRotate(valueB ^ valueA, valueA) + secretTable[2 * i + 1];
    }
    leftWord = valueA;
    rightWord = valueB;
}

// Расшифрование одного 8-байтового блока
void RC5::decryptBlock(uint32_t& leftWord, uint32_t& rightWord) {
    uint32_t valueA = leftWord;
    uint32_t valueB = rightWord;
    for (int i = roundCount; i > 0; i--) {
        valueB = rightRotate(valueB - secretTable[2 * i + 1], valueA) ^ valueA;
        valueA = rightRotate(valueA - secretTable[2 * i], valueB) ^ valueB;
    }
    leftWord = valueA - secretTable[0]; // ИСПРАВЛЕНО: добавлен индекс [0]
    rightWord = valueB - secretTable[0]; // ИСПРАВЛЕНО: добавлен индекс [0]
}
