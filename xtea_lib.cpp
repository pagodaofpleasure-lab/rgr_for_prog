// xtea_lib.cpp
// Компиляция: g++ -shared -fPIC -o algorithms/xtea.so xtea_lib.cpp

#include "algorithm_interface.h"
#include "utils.h"
#include <string>
#include <vector>
#include <cstring>
#include <cstdint>
using namespace std;

static string g_resultString;
static vector<unsigned char> g_resultData;

static const unsigned int DELTA = 0x9E3779B9;
static const int FEISTEL_СYCLE = 32; // 64 - rounds

static void xteaEncryptBlock(unsigned char out[8], const unsigned char in[8], const unsigned int key[4]) {
    unsigned int v0, v1;
    memcpy(&v0, in, 4);
    memcpy(&v1, in + 4, 4);
    unsigned int sum = 0;

    for (int i = 0; i < FEISTEL_СYCLE; ++i) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        sum += DELTA;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
    }

    memcpy(out, &v0, 4);
    memcpy(out + 4, &v1, 4);
}

static void xteaDecryptBlock(unsigned char out[8], const unsigned char in[8], const unsigned int key[4]) {
    unsigned int v0, v1;
    memcpy(&v0, in, 4);
    memcpy(&v1, in + 4, 4);
    unsigned int sum = DELTA * FEISTEL_СYCLE;

    for (int i = 0; i < FEISTEL_СYCLE; ++i) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
        sum -= DELTA;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    }

    memcpy(out, &v0, 4);
    memcpy(out + 4, &v1, 4);
}

static void loadKey(const char* key, unsigned int k[4]) {
    unsigned char buf[16];
    copyKey(key, buf, 16);
    memcpy(k, buf, 16);
}

static vector<unsigned char> encryptBlocks(const vector<unsigned char>& data, const char* key) {
    unsigned int k[4];
    loadKey(key, k);
    vector<unsigned char> padded = pkcs7Pad(data, 8);
    vector<unsigned char> out;

    for (size_t i = 0; i < padded.size(); i += 8) {
        unsigned char block[8];
        xteaEncryptBlock(block, &padded[i], k);
        out.insert(out.end(), block, block + 8);
    }
    return out;
}
static vector<unsigned char> decryptBlocks(const vector<unsigned char>& data, const char* key) {
    if (data.size() % 8 != 0) {
        return {};
    }
    unsigned int k[4];
    loadKey(key, k);
    vector<unsigned char> out;

    for (size_t i = 0; i < data.size(); i += 8) {
        unsigned char block[8];
        xteaDecryptBlock(block, &data[i], k);
        out.insert(out.end(), block, block + 8);
    }
    return pkcs7Unpad(out);
}

static vector<unsigned char> encryptFileData(const vector<unsigned char>& data, const char* key) {
    unsigned char iv[8];
    randomBytes(iv, 8);
    unsigned int k[4];
    loadKey(key, k);

    vector<unsigned char> padded = pkcs7Pad(data, 8);
    vector<unsigned char> prev(iv, iv + 8);
    vector<unsigned char> out(iv, iv + 8);

    for (size_t i = 0; i < padded.size(); i += 8) {
        unsigned char xored[8];
        for (int j = 0; j < 8; ++j) {
            xored[j] = padded[i + j] ^ prev[j];
        }
        unsigned char block[8];
        xteaEncryptBlock(block, xored, k);
        out.insert(out.end(), block, block + 8);
        memcpy(prev.data(), block, 8);
    }
    return out;
}

static vector<unsigned char> decryptFileData(const vector<unsigned char>& data, const char* key) {
    if (data.size() < 16 || (data.size() - 8) % 8 != 0) {
        return {};
    }
    unsigned int k[4];
    loadKey(key, k);
    vector<unsigned char> prev(data.begin(), data.begin() + 8);
    vector<unsigned char> out;

    for (size_t i = 8; i < data.size(); i += 8) {
        unsigned char block[8];
        xteaDecryptBlock(block, &data[i], k);
        for (int j = 0; j < 8; ++j) {
            out.push_back(block[j] ^ prev[j]);
        }
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
    return "XTEA";
}

void free_memory(void* ptr) {}

}
