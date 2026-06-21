// g++ -shared -fPIC -o algorithms/rc5.so rc5_lib.cpp

// RC5-32/12/16
#include "algorithm_interface.h"
#include "utils.h"
#include <string>
#include <vector>
#include <cstring>
#include <cstdint>

using namespace std;

static string g_resultString;
static vector<unsigned char> g_resultData;

static const int ROUNDS = 12; // число раундов
static const int TABLE_SIZE = 2 * (ROUNDS + 1); 

// Сдвиг влево
static unsigned int rotl(unsigned int v, unsigned int s) {
    s &= 31;
    return (v << s) | (v >> (32 - s));
}
// Сдвиг вправо
static unsigned int rotr(unsigned int v, unsigned int s) {
    s &= 31;
    return (v >> s) | (v << (32 - s));
}

static void expandKey(const unsigned char key[16], unsigned int s[TABLE_SIZE]) {
    unsigned int l[4] = {0};
    for (int i = 0; i < 16; ++i) {
        l[i / 4] |= ((unsigned int)key[i]) << (8 * (i % 4));
    }

    s[0] = 0xB7E15163; // P32
    for (int i = 1; i < TABLE_SIZE; ++i) {
        s[i] = s[i - 1] + 0x9E3779B9; // Q32
    }

    unsigned int a = 0, b = 0;
    int steps = 3 * (TABLE_SIZE > 4 ? TABLE_SIZE : 4);
    int i = 0, j = 0;
    for (int k = 0; k < steps; ++k) {
        a = s[i] = rotl(s[i] + a + b, 3);
        b = l[j] = rotl(l[j] + a + b, (a + b) & 31);
        i = (i + 1) % TABLE_SIZE;
        j = (j + 1) % 4;
    }
}

static void rc5EncryptBlock(unsigned int& a, unsigned int& b, const unsigned int s[TABLE_SIZE]) {
    a += s[0];
    b += s[1];
    for (int i = 1; i <= ROUNDS; ++i) {
        a = rotl(a ^ b, b & 31) + s[2 * i];
        b = rotl(b ^ a, a & 31) + s[2 * i + 1];
    }
}

static void rc5DecryptBlock(unsigned int& a, unsigned int& b, const unsigned int s[TABLE_SIZE]) {
    for (int i = ROUNDS; i >= 1; --i) {
        b = rotr(b - s[2 * i + 1], a & 31) ^ a;
        a = rotr(a - s[2 * i], b & 31) ^ b;
    }
    b -= s[1];
    a -= s[0];
}

static vector<unsigned char> encryptBlocks(const vector<unsigned char>& data, const char* key) {
    unsigned char k[16];
    copyKey(key, k, 16);
    unsigned int s[TABLE_SIZE];
    expandKey(k, s);

    vector<unsigned char> padded = pkcs7Pad(data, 8);
    vector<unsigned char> out;

    for (size_t i = 0; i < padded.size(); i += 8) {
        unsigned int a, b;
        memcpy(&a, &padded[i], 4);
        memcpy(&b, &padded[i + 4], 4);
        rc5EncryptBlock(a, b, s);
        unsigned char block[8];
        memcpy(block, &a, 4);
        memcpy(block + 4, &b, 4);
        out.insert(out.end(), block, block + 8);
    }
    return out;
}

static vector<unsigned char> decryptBlocks(const vector<unsigned char>& data, const char* key) {
    if (data.size() % 8 != 0) {
        return {};
    }
    unsigned char k[16];
    copyKey(key, k, 16);
    unsigned int s[TABLE_SIZE];
    expandKey(k, s);

    vector<unsigned char> out;
    for (size_t i = 0; i < data.size(); i += 8) {
        unsigned int a, b;
        memcpy(&a, &data[i], 4);
        memcpy(&b, &data[i + 4], 4);
        rc5DecryptBlock(a, b, s);
        unsigned char block[8];
        memcpy(block, &a, 4);
        memcpy(block + 4, &b, 4);
        out.insert(out.end(), block, block + 8);
    }
    return pkcs7Unpad(out);
}

static vector<unsigned char> encryptFileData(const vector<unsigned char>& data, const char* key) {
    unsigned char iv[8];
    randomBytes(iv, 8);
    unsigned char k[16];
    copyKey(key, k, 16);
    unsigned int s[TABLE_SIZE];
    expandKey(k, s);

    vector<unsigned char> padded = pkcs7Pad(data, 8);
    vector<unsigned char> prev(iv, iv + 8);
    vector<unsigned char> out(iv, iv + 8);

    for (size_t i = 0; i < padded.size(); i += 8) {
        unsigned char xored[8];
        for (int j = 0; j < 8; ++j) {
            xored[j] = padded[i + j] ^ prev[j];
        }
        unsigned int a, b;
        memcpy(&a, xored, 4);
        memcpy(&b, xored + 4, 4);
        rc5EncryptBlock(a, b, s);
        unsigned char block[8];
        memcpy(block, &a, 4);
        memcpy(block + 4, &b, 4);
        out.insert(out.end(), block, block + 8);
        memcpy(prev.data(), block, 8);
    }
    return out;
}

static vector<unsigned char> decryptFileData(const vector<unsigned char>& data, const char* key) {
    if (data.size() < 16 || (data.size() - 8) % 8 != 0) {
        return {};
    }
    unsigned char k[16];
    copyKey(key, k, 16);
    unsigned int s[TABLE_SIZE];
    expandKey(k, s);

    vector<unsigned char> prev(data.begin(), data.begin() + 8);
    vector<unsigned char> out;

    for (size_t i = 8; i < data.size(); i += 8) {
        unsigned int a, b;
        memcpy(&a, &data[i], 4);
        memcpy(&b, &data[i + 4], 4);
        rc5DecryptBlock(a, b, s);
        unsigned char block[8];
        memcpy(block, &a, 4);
        memcpy(block + 4, &b, 4);
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
    return "Ключ: от 1 до 16 символов (дополняется нулями до 16)";
}

int is_valid_key(const char* key) {
    if (!key) return 0;
    size_t len = strlen(key);
    return len >= 1 && len <= 16;
}

const char* get_algorithm_name() {
    return "RC5-32/12/16";
}

void free_memory(void* ptr) {}

}