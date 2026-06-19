#include "rc5.h"
#include <fstream>
#include <stdexcept>

using namespace std;

// PKCS#7
void padBuffer(vector<uint8_t>& buffer) {
    uint8_t paddingSize = 8 - (buffer.size() % 8);
    for (int i = 0; i < paddingSize; i++) {
        buffer.push_back(paddingSize);
    }
}

// Удаление дополнения после расшифрования
bool unpadBuffer(vector<uint8_t>& buffer) {
    if (buffer.empty() || buffer.size() % 8 != 0) return false;
    uint8_t paddingSize = buffer.back();
    if (paddingSize == 0 || paddingSize > 8) return false;
    
    for (size_t i = buffer.size() - paddingSize; i < buffer.size(); i++) {
        if (buffer[i] != paddingSize) return false;
    }
    buffer.resize(buffer.size() - paddingSize);
    return true;
}

// Шифрование массива байт в режиме CBC
vector<uint8_t> encryptCbc(RC5& cipher, const vector<uint8_t>& plainTextBytes, const vector<uint8_t>& initVector) {
    vector<uint8_t> dataBuffer = plainTextBytes;
    padBuffer(dataBuffer);

    vector<uint8_t> cipherTextBytes(dataBuffer.size());
    uint32_t prevLeft = 0, prevRight = 0;
    
    for (int i = 0; i < 4; i++) {
        prevLeft |= (uint32_t)initVector[i] << (8 * i);
        prevRight |= (uint32_t)initVector[i + 4] << (8 * i);
    }

    for (size_t offset = 0; offset < dataBuffer.size(); offset += 8) {
        uint32_t curLeft = 0, curRight = 0;
        for (int i = 0; i < 4; i++) {
            curLeft |= (uint32_t)dataBuffer[offset + i] << (8 * i);
            curRight |= (uint32_t)dataBuffer[offset + 4 + i] << (8 * i);
        }

        curLeft ^= prevLeft;
        curRight ^= prevRight;

        cipher.encryptBlock(curLeft, curRight);

        prevLeft = curLeft;
        prevRight = curRight;

        for (int i = 0; i < 4; i++) {
            cipherTextBytes[offset + i] = (curLeft >> (8 * i)) & 0xFF;
            cipherTextBytes[offset + 4 + i] = (curRight >> (8 * i)) & 0xFF;
        }
    }
    return cipherTextBytes;
}

// Расшифрование массива байт в режиме CBC 
vector<uint8_t> decryptCbc(RC5& cipher, const vector<uint8_t>& cipherTextBytes, const vector<uint8_t>& initVector) {
    if (cipherTextBytes.size() % 8 != 0) throw invalid_argument("Неверный размер данных");

    vector<uint8_t> plainTextBytes(cipherTextBytes.size());
    uint32_t prevLeft = 0, prevRight = 0;

    for (int i = 0; i < 4; i++) {
        prevLeft |= (uint32_t)initVector[i] << (8 * i);
        prevRight |= (uint32_t)initVector[i + 4] << (8 * i);
    }

    for (size_t offset = 0; offset < cipherTextBytes.size(); offset += 8) {
        uint32_t nextPrevLeft = 0, nextPrevRight = 0;
        uint32_t curLeft = 0, curRight = 0;

        for (int i = 0; i < 4; i++) {
            curLeft |= (uint32_t)cipherTextBytes[offset + i] << (8 * i);
            curRight |= (uint32_t)cipherTextBytes[offset + 4 + i] << (8 * i);
        }

        nextPrevLeft = curLeft;
        nextPrevRight = curRight;

        cipher.decryptBlock(curLeft, curRight);

        curLeft ^= prevLeft;
        curRight ^= prevRight;

        prevLeft = nextPrevLeft;
        prevRight = nextPrevRight;

        // Перенос 32-битных регистров обратно в байты
        for (int i = 0; i < 4; i++) {
            plainTextBytes[offset + i] = (curLeft >> (8 * i)) & 0xFF;
            plainTextBytes[offset + 4 + i] = (curRight >> (8 * i)) & 0xFF;
        }
    }

    if (!unpadBuffer(plainTextBytes)) {
        throw runtime_error("Ошибка дополнения");
    }
    return plainTextBytes;
}

// Функция шифрования файла
bool encryptFile(RC5& cipher, const string& inputPath, const string& outputPath, const vector<uint8_t>& initVector) {
    ifstream inputFile(inputPath, ios::binary);
    if (!inputFile) return false;
    
    vector<uint8_t> buffer((istreambuf_iterator<char>(inputFile)), istreambuf_iterator<char>());
    inputFile.close();

    vector<uint8_t> encrypted = encryptCbc(cipher, buffer, initVector);

    ofstream outputFile(outputPath, ios::binary);
    if (!outputFile) return false;
    outputFile.write(reinterpret_cast<const char*>(encrypted.data()), encrypted.size());
    return true;
}

// Функция расшифрования файла
bool decryptFile(RC5& cipher, const string& inputPath, const string& outputPath, const vector<uint8_t>& initVector) {
    ifstream inputFile(inputPath, ios::binary);
    if (!inputFile) return false;

    vector<uint8_t> buffer((istreambuf_iterator<char>(inputFile)), istreambuf_iterator<char>());
    inputFile.close();

    try {
        vector<uint8_t> decrypted = decryptCbc(cipher, buffer, initVector);
        ofstream outputFile(outputPath, ios::binary);
        if (!outputFile) return false;
        outputFile.write(reinterpret_cast<const char*>(decrypted.data()), decrypted.size());
        return true;
    } catch (...) {
        return false;
    }
}
