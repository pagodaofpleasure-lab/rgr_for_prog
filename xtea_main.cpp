#include <iostream>
#include <vector>
#include <cstdint>
#include <iomanip>
#include "xtea.h"

using namespace std;

void printHex(const string& label, const uint8_t* data, size_t length) {
    cout << label << ": ";
    for (size_t i = 0; i < length; i++) {
        cout << hex << uppercase << setw(2) << setfill('0') << (int)data[i] << " ";
    }
    cout << dec << endl; 
}

int main() {
    // 128-битный секретный ключ (16 байт)
    vector<uint8_t> secretKey = {
        '1', '2', '3', '4', '5', '6', '7', '8', 
        '9', '0', '1', '2', '3', '4', '5', '6'
    };
    
    uint8_t plaintextBlock[8] = {'T', 'E', 'S', 'T', 'X', 'T', 'E', 'A'};
    
    uint8_t ciphertextBlock[8] = {0};
    uint8_t decryptedBlock[8] = {0};

    try {
        Xtea cipher(secretKey);


        printHex("Исходные данные (HEX)", plaintextBlock, 8);
        cout << "Исходные данные (строка) : ";
        for (int i = 0; i < 8; i++) cout << plaintextBlock[i];
        cout << endl;
        
        cipher.encryptBlock(plaintextBlock, ciphertextBlock);
        printHex("Зашифрованный блок ", ciphertextBlock, 8);

        cipher.decryptBlock(ciphertextBlock, decryptedBlock);
        printHex("Расшифрованный блок ", decryptedBlock, 8);
        
        cout << "Восстановленный текст : ";
        for (int i = 0; i < 8; i++) cout << decryptedBlock[i];
        cout << endl ;

    } catch (const exception& error) {
        cerr << "Произошла ошибка: " << error.what() << endl;
        return 1;
    }

    return 0;
}