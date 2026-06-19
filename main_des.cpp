#include <iostream>
#include <fstream>
#include <string>
#include <cstdint>
#include "des.h"

using namespace std;

void processFile(const string& inP, const string& outP, uint64_t key, bool encrypt) {
    ifstream in(inP, ios::binary);
    ofstream out(outP, ios::binary);
    if (!in || !out) return;

    DES des(key);
    in.seekg(0, ios::end);
    uint64_t fileSize = in.tellg();
    in.seekg(0, ios::beg);

    if (encrypt) {
        uint8_t padding = 8 - (fileSize % 8);
        for (uint64_t i = 0; i < fileSize / 8; ++i) {
            uint64_t block = 0;
            in.read(reinterpret_cast<char*>(&block), 8);
            // Reverse bytes for correct bit order
            uint64_t swapped = 0;
            for(int j=0; j<8; ++j) swapped |= (uint64_t)((uint8_t*)&block)[j] << (56 - j*8);
            uint64_t res = des.encrypt(swapped);
            for(int j=0; j<8; ++j) {
                uint8_t b = (res >> (56 - j*8)) & 0xFF;
                out.write(reinterpret_cast<char*>(&b), 1);
            }
        }
        uint64_t last = 0;
        uint8_t rem = fileSize % 8;
        if (rem > 0) in.read(reinterpret_cast<char*>(&last), rem);
        for (int i = rem; i < 8; ++i) ((uint8_t*)&last)[i] = padding;
        
        uint64_t swapped = 0;
        for(int j=0; j<8; ++j) swapped |= (uint64_t)((uint8_t*)&last)[j] << (56 - j*8);
        uint64_t res = des.encrypt(swapped);
        for(int j=0; j<8; ++j) {
            uint8_t b = (res >> (56 - j*8)) & 0xFF;
            out.write(reinterpret_cast<char*>(&b), 1);
        }
        if (rem == 0) { // Special case for full block padding
             uint64_t pBlock = 0;
             for(int j=0; j<8; ++j) ((uint8_t*)&pBlock)[j] = 8;
             uint64_t swp = 0;
             for(int j=0; j<8; ++j) swp |= (uint64_t)((uint8_t*)&pBlock)[j] << (56 - j*8);
             uint64_t r = des.encrypt(swp);
             for(int j=0; j<8; ++j) {
                uint8_t b = (r >> (56 - j*8)) & 0xFF;
                out.write(reinterpret_cast<char*>(&b), 1);
             }
        }
    } else {
        uint64_t blocks = fileSize / 8;
        for (uint64_t i = 0; i < blocks; ++i) {
            uint64_t block = 0;
            in.read(reinterpret_cast<char*>(&block), 8);
            uint64_t swapped = 0;
            for(int j=0; j<8; ++j) swapped |= (uint64_t)((uint8_t*)&block)[j] << (56 - j*8);
            uint64_t res = des.decrypt(swapped);
            uint8_t outB[8];
            for(int j=0; j<8; ++j) outB[j] = (res >> (56 - j*8)) & 0xFF;
            
            if (i == blocks - 1) {
                uint8_t pad = outB[7];
                if (pad <= 8) out.write(reinterpret_cast<char*>(outB), 8 - pad);
                else out.write(reinterpret_cast<char*>(outB), 8);
            } else {
                out.write(reinterpret_cast<char*>(outB), 8);
            }
        }
    }
}

int main() {
    cout << "DES Tool. Usage: Enter mode (1-Enc, 2-Dec), input file, output file and 8-char key." << endl;
    int mode;
    string inP, outP, keyStr;
    if (!(cin >> mode >> inP >> outP >> keyStr)) return 1;
    
    uint64_t key = 0;
    for (int i = 0; i < 8 && i < keyStr.size(); ++i) 
        key |= (uint64_t)(uint8_t)keyStr[i] << (56 - i * 8);

    processFile(inP, outP, key, mode == 1);
    cout << "Done." << endl;
    return 0;
}
