// des_lib.cpp
// Компиляция: g++ -shared -fPIC -o algorithms/des.so des_lib.cpp

#include "algorithm_interface.h"
#include "utils.h"
#include <string>
#include <vector>
#include <cstring>
#include <cstdint>
using namespace std;

static string g_resultString;
static vector<unsigned char> g_resultData;

static const unsigned char IP[] = {
    58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
    57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7
};
static const unsigned char FP[] = {
    40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,
    36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25
};
static const unsigned char E[] = {
    32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,
    22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1
};
static const unsigned char P[] = {
    16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25
};
static const unsigned char PC1[] = {
    57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,
    31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4
};
static const unsigned char PC2[] = {
    14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,
    51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32
};
static const unsigned char shifts[] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
static const unsigned char S[8][64] = {
    {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13},
    {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9},
    {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12},
    {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14},
    {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3},
    {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13},
    {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12},
    {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}
};

static uint64_t permute(uint64_t val, const unsigned char* table, int n) {
    uint64_t res = 0;
    for (int i = 0; i < n; ++i) {
        if ((val >> (64 - table[i])) & 1) {
            res |= (1ULL << (n - 1 - i));
        }
    }
    return res;
}

static void makeSubkeys(uint64_t key, uint64_t subkeys[16]) {
    uint64_t pc1 = permute(key, PC1, 56);
    uint32_t C = (uint32_t)((pc1 >> 28) & 0x0FFFFFFF);
    uint32_t D = (uint32_t)(pc1 & 0x0FFFFFFF);
    for (int i = 0; i < 16; ++i) {
        for (int j = 0; j < shifts[i]; ++j) {
            C = ((C << 1) & 0x0FFFFFFF) | (C >> 27);
            D = ((D << 1) & 0x0FFFFFFF) | (D >> 27);
        }
        subkeys[i] = permute(((uint64_t)C << 28) | D, PC2, 48);
    }
}

static uint32_t f(uint32_t R, uint64_t k) {
    uint64_t e = permute((uint64_t)R << 32, E, 48) ^ k;
    uint32_t res = 0;
    for (int i = 0; i < 8; ++i) {
        uint8_t val = (uint8_t)((e >> (42 - i * 6)) & 0x3F);
        uint8_t row = ((val >> 4) & 2) | (val & 1);
        uint8_t col = (val >> 1) & 0x0F;
        res = (res << 4) | S[i][row * 16 + col];
    }
    return (uint32_t)permute((uint64_t)res << 32, P, 32);
}

static void desEncryptBlock(const unsigned char in[8], unsigned char out[8], const unsigned char key[8]) {
    uint64_t block = 0;
    for (int i = 0; i < 8; ++i) block |= (uint64_t)in[i] << (56 - i * 8);
    uint64_t k64 = 0;
    for (int i = 0; i < 8; ++i) k64 |= (uint64_t)key[i] << (56 - i * 8);
    uint64_t subkeys[16];
    makeSubkeys(k64, subkeys);
    block = permute(block, IP, 64);
    uint32_t L = (uint32_t)(block >> 32), R = (uint32_t)block;
    for (int i = 0; i < 16; ++i) { uint32_t t = R; R = L ^ f(R, subkeys[i]); L = t; }
    uint64_t result = permute(((uint64_t)R << 32) | L, FP, 64);
    for (int i = 0; i < 8; ++i) out[i] = (unsigned char)((result >> (56 - i * 8)) & 0xFF);
}

static void desDecryptBlock(const unsigned char in[8], unsigned char out[8], const unsigned char key[8]) {
    uint64_t block = 0;
    for (int i = 0; i < 8; ++i) block |= (uint64_t)in[i] << (56 - i * 8);
    uint64_t k64 = 0;
    for (int i = 0; i < 8; ++i) k64 |= (uint64_t)key[i] << (56 - i * 8);
    uint64_t subkeys[16];
    makeSubkeys(k64, subkeys);
    block = permute(block, IP, 64);
    uint32_t L = (uint32_t)(block >> 32), R = (uint32_t)block;
    for (int i = 15; i >= 0; --i) { uint32_t t = R; R = L ^ f(R, subkeys[i]); L = t; }
    uint64_t result = permute(((uint64_t)R << 32) | L, FP, 64);
    for (int i = 0; i < 8; ++i) out[i] = (unsigned char)((result >> (56 - i * 8)) & 0xFF);
}

static vector<unsigned char> encryptBlocks(const vector<unsigned char>& data, const char* key) {
    unsigned char k[8];
    copyKey(key, k, 8);
    vector<unsigned char> padded = pkcs7Pad(data, 8);
    vector<unsigned char> out;
    for (size_t i = 0; i < padded.size(); i += 8) {
        unsigned char block[8];
        desEncryptBlock(&padded[i], block, k);
        out.insert(out.end(), block, block + 8);
    }
    return out;
}

static vector<unsigned char> decryptBlocks(const vector<unsigned char>& data, const char* key) {
    if (data.size() % 8 != 0) return {};
    unsigned char k[8];
    copyKey(key, k, 8);
    vector<unsigned char> out;
    for (size_t i = 0; i < data.size(); i += 8) {
        unsigned char block[8];
        desDecryptBlock(&data[i], block, k);
        out.insert(out.end(), block, block + 8);
    }
    return pkcs7Unpad(out);
}

static vector<unsigned char> encryptFileData(const vector<unsigned char>& data, const char* key) {
    unsigned char iv[8], k[8];
    randomBytes(iv, 8);
    copyKey(key, k, 8);
    vector<unsigned char> padded = pkcs7Pad(data, 8);
    vector<unsigned char> prev(iv, iv + 8), out(iv, iv + 8);
    for (size_t i = 0; i < padded.size(); i += 8) {
        unsigned char xored[8], block[8];
        for (int j = 0; j < 8; ++j) xored[j] = padded[i + j] ^ prev[j];
        desEncryptBlock(xored, block, k);
        out.insert(out.end(), block, block + 8);
        memcpy(prev.data(), block, 8);
    }
    return out;
}

static vector<unsigned char> decryptFileData(const vector<unsigned char>& data, const char* key) {
    if (data.size() < 16 || (data.size() - 8) % 8 != 0) return {};
    unsigned char k[8];
    copyKey(key, k, 8);
    vector<unsigned char> prev(data.begin(), data.begin() + 8), out;
    for (size_t i = 8; i < data.size(); i += 8) {
        unsigned char block[8];
        desDecryptBlock(&data[i], block, k);
        for (int j = 0; j < 8; ++j) out.push_back(block[j] ^ prev[j]);
        memcpy(prev.data(), &data[i], 8);
    }
    return pkcs7Unpad(out);
}

extern "C" {

const char* encrypt_text(const char* text, const char* key) {
    vector<unsigned char> input(text, text + strlen(text));
    g_resultString = bytesToHex(encryptBlocks(input, key));
    return g_resultString.c_str();
}

const char* decrypt_text(const char* cipher, const char* key) {
    vector<unsigned char> data = hexToBytes(cipher);
    vector<unsigned char> plain = decryptBlocks(data, key);
    g_resultString = string(plain.begin(), plain.end());
    return g_resultString.c_str();
}

unsigned char* encrypt_data(const unsigned char* data, int dataSize, const char* key, int* outSize) {
    vector<unsigned char> input(data, data + dataSize);
    g_resultData = encryptFileData(input, key);
    *outSize = (int)g_resultData.size();
    return g_resultData.data();
}

unsigned char* decrypt_data(const unsigned char* data, int dataSize, const char* key, int* outSize) {
    vector<unsigned char> input(data, data + dataSize);
    g_resultData = decryptFileData(input, key);
    *outSize = (int)g_resultData.size();
    return g_resultData.data();
}

const char* generate_key() {
    g_resultString = randomKeyString(8);
    return g_resultString.c_str();
}

const char* get_key_hint() {
    return "Ключ: ровно 8 символов";
}

int is_valid_key(const char* key) {
    return key && strlen(key) == 8;
}

const char* get_algorithm_name() {
    return "DES";
}

void free_memory(void* ptr) {}

}
