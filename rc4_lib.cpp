// rc4_lib.cpp
// Компиляция: g++ -shared -fPIC -o algorithms/rc4.so rc4_lib.cpp

#include "algorithm_interface.h"
#include "utils.h"
#include <string>
#include <vector>
#include <cstring>
using namespace std;

static string g_resultString;
static vector<unsigned char> g_resultData;

static vector<unsigned char> rc4Crypt(const vector<unsigned char>& data, const vector<unsigned char>& key) {
    unsigned char s[256];
    for (int i = 0; i < 256; ++i) {
        s[i] = (unsigned char)i;
    }

    int j = 0;
    for (int i = 0; i < 256; ++i) {
        j = (j + s[i] + key[i % key.size()]) & 255;
        unsigned char t = s[i];
        s[i] = s[j];
        s[j] = t;
    }

    vector<unsigned char> out;
    int i = 0;
    j = 0;
    for (size_t k = 0; k < data.size(); ++k) {
        i = (i + 1) & 255;
        j = (j + s[i]) & 255;
        unsigned char t = s[i];
        s[i] = s[j];
        s[j] = t;
        unsigned char b = s[(s[i] + s[j]) & 255];
        out.push_back(data[k] ^ b);
    }
    return out;
}

static vector<unsigned char> encryptAll(const vector<unsigned char>& data, const char* key) {
    vector<unsigned char> k(key, key + strlen(key));
    return rc4Crypt(data, k);
}

extern "C" {

const char* encrypt_text(const char* text, const char* key) {
    vector<unsigned char> input(text, text + strlen(text));
    g_resultString = bytesToHex(encryptAll(input, key));
    return g_resultString.c_str();
}

const char* decrypt_text(const char* cipher, const char* key) {
    vector<unsigned char> data = hexToBytes(cipher);
    vector<unsigned char> plain = encryptAll(data, key);
    g_resultString = string(plain.begin(), plain.end());
    return g_resultString.c_str();
}

unsigned char* encrypt_data(const unsigned char* data, int dataSize, const char* key, int* outSize) {
    vector<unsigned char> input(data, data + dataSize);
    g_resultData = encryptAll(input, key);
    *outSize = (int)g_resultData.size();
    return g_resultData.data();
}

unsigned char* decrypt_data(const unsigned char* data, int dataSize, const char* key, int* outSize) {
    vector<unsigned char> input(data, data + dataSize);
    g_resultData = encryptAll(input, key);
    *outSize = (int)g_resultData.size();
    return g_resultData.data();
}

const char* generate_key() {
    g_resultString = randomKeyString(8);
    return g_resultString.c_str();
}

const char* get_key_hint() {
    return "Ключ: от 1 до 256 символов";
}

int is_valid_key(const char* key) {
    if (!key) return 0;
    size_t len = strlen(key);
    return len >= 1 && len <= 256;
}

const char* get_algorithm_name() {
    return "RC4";
}

void free_memory(void* ptr) {}

}
