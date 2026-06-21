// speck_lib.cpp
// Компиляция: g++ -shared -fPIC -o algorithms/speck.so speck_lib.cpp

#include "algorithm_interface.h"
#include "utils.h"
#include <string>
#include <vector>
#include <cstring>
#include <cstdint>
using namespace std;

static string g_resultString;
static vector<unsigned char> g_resultData;

static uint64_t ror64(uint64_t x, int r) {
    return (x >> r) | (x << (64 - r));
}

static uint64_t rol64(uint64_t x, int r) {
    return (x << r) | (x >> (64 - r));
}

static void speckRound(uint64_t& x, uint64_t& y, uint64_t k) {
    x = ror64(x, 8);
    x += y;
    x ^= k;
    y = rol64(y, 3);
    y ^= x;
}

static void speckRoundBack(uint64_t& x, uint64_t& y, uint64_t k) {
    y ^= x;
    y = ror64(y, 3);
    x ^= k;
    x -= y;
    x = rol64(x, 8);
}

static void speckEncryptBlock(const unsigned char in[16], unsigned char out[16], const unsigned char key[16]) {
    uint64_t y, x, b, a;
    memcpy(&y, in, 8);
    memcpy(&x, in + 8, 8);
    memcpy(&b, key, 8);
    memcpy(&a, key + 8, 8);

    uint64_t keys[33];
    keys[0] = b;
    speckRound(x, y, b);
    for (int i = 0; i < 31; ++i) {
        speckRound(a, b, i);
        keys[i + 1] = b;
        speckRound(x, y, b);
    }

    memcpy(out, &y, 8);
    memcpy(out + 8, &x, 8);
}

static void speckDecryptBlock(const unsigned char in[16], unsigned char out[16], const unsigned char key[16]) {
    uint64_t y, x, b, a;
    memcpy(&y, in, 8);
    memcpy(&x, in + 8, 8);
    memcpy(&b, key, 8);
    memcpy(&a, key + 8, 8);

    uint64_t keys[33];
    keys[0] = b;
    for (int i = 0; i < 31; ++i) {
        speckRound(a, b, i);
        keys[i + 1] = b;
    }

    for (int i = 31; i > 0; --i) {
        speckRoundBack(x, y, keys[i]);
    }
    speckRoundBack(x, y, keys[0]);

    memcpy(out, &y, 8);
    memcpy(out + 8, &x, 8);
}

static vector<unsigned char> encryptBlocks(const vector<unsigned char>& data, const char* key) {
    unsigned char k[16];
    copyKey(key, k, 16);
    vector<unsigned char> padded = pkcs7Pad(data, 16);
    vector<unsigned char> out;

    for (size_t i = 0; i < padded.size(); i += 16) {
        unsigned char block[16];
        speckEncryptBlock(&padded[i], block, k);
        out.insert(out.end(), block, block + 16);
    }
    return out;
}

static vector<unsigned char> decryptBlocks(const vector<unsigned char>& data, const char* key) {
    if (data.size() % 16 != 0) {
        return {};
    }
    unsigned char k[16];
    copyKey(key, k, 16);
    vector<unsigned char> out;

    for (size_t i = 0; i < data.size(); i += 16) {
        unsigned char block[16];
        speckDecryptBlock(&data[i], block, k);
        out.insert(out.end(), block, block + 16);
    }
    return pkcs7Unpad(out);
}

static vector<unsigned char> encryptFileData(const vector<unsigned char>& data, const char* key) {
    unsigned char iv[16];
    randomBytes(iv, 16);
    unsigned char k[16];
    copyKey(key, k, 16);

    vector<unsigned char> padded = pkcs7Pad(data, 16);
    vector<unsigned char> prev(iv, iv + 16);
    vector<unsigned char> out(iv, iv + 16);

    for (size_t i = 0; i < padded.size(); i += 16) {
        unsigned char xored[16];
        for (int j = 0; j < 16; ++j) {
            xored[j] = padded[i + j] ^ prev[j];
        }
        unsigned char block[16];
        speckEncryptBlock(xored, block, k);
        out.insert(out.end(), block, block + 16);
        memcpy(prev.data(), block, 16);
    }
    return out;
}

static vector<unsigned char> decryptFileData(const vector<unsigned char>& data, const char* key) {
    if (data.size() < 32 || (data.size() - 16) % 16 != 0) {
        return {};
    }
    unsigned char k[16];
    copyKey(key, k, 16);
    vector<unsigned char> prev(data.begin(), data.begin() + 16);
    vector<unsigned char> out;

    for (size_t i = 16; i < data.size(); i += 16) {
        unsigned char block[16];
        speckDecryptBlock(&data[i], block, k);
        for (int j = 0; j < 16; ++j) {
            out.push_back(block[j] ^ prev[j]);
        }
        memcpy(prev.data(), &data[i], 16);
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
    g_resultString = randomKeyString(16);
    return g_resultString.c_str();
}

const char* get_key_hint() {
    return "Ключ: ровно 16 символов";
}

int is_valid_key(const char* key) {
    return key && strlen(key) == 16;
}

const char* get_algorithm_name() {
    return "Speck 128/128";
}

void free_memory(void* ptr) {}

}
