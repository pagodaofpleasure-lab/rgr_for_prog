// hill_lib.cpp
// Компиляция: g++ -shared -fPIC -o algorithms/hill.so hill_lib.cpp

#include "algorithm_interface.h"
#include "utils.h"
#include <string>
#include <vector>
#include <cstring>
using namespace std;

static string g_resultString;
static vector<unsigned char> g_resultData;

static int det2(const unsigned char m[4]) {
    int d = m[0] * m[3] - m[1] * m[2];
    return (d % 256 + 256) % 256;
}

static int invMod(int a) {
    a = (a % 256 + 256) % 256;
    for (int x = 1; x < 256; x += 2) {
        if ((a * x) % 256 == 1) {
            return x;
        }
    }
    return -1;
}

static bool invertMatrix(const unsigned char key[4], unsigned char inv[4]) {
    int invDet = invMod(det2(key));
    if (invDet < 0) {
        return false;
    }
    inv[0] = (unsigned char)((key[3] * invDet) % 256);
    inv[1] = (unsigned char)(((256 - key[1]) * invDet) % 256);
    inv[2] = (unsigned char)(((256 - key[2]) * invDet) % 256);
    inv[3] = (unsigned char)((key[0] * invDet) % 256);
    return true;
}

static vector<unsigned char> hillProcess(const vector<unsigned char>& data, const unsigned char m[4], bool encrypt) {
    vector<unsigned char> buf = data;
    if (encrypt) {
        buf = pkcs7Pad(buf, 2);
    } else if (buf.size() % 2 != 0) {
        return {};
    }

    vector<unsigned char> out;
    for (size_t i = 0; i < buf.size(); i += 2) {
        int x = buf[i];
        int y = buf[i + 1];
        int nx = (m[0] * x + m[1] * y) % 256;
        int ny = (m[2] * x + m[3] * y) % 256;
        out.push_back((unsigned char)nx);
        out.push_back((unsigned char)ny);
    }

    if (!encrypt) {
        return pkcs7Unpad(out);
    }
    return out;
}

static vector<unsigned char> doEncrypt(const vector<unsigned char>& data, const char* key) {
    if (!key || strlen(key) != 4) {
        return {};
    }
    unsigned char m[4];
    memcpy(m, key, 4);
    if (invMod(det2(m)) < 0) {
        return {};
    }
    
    return hillProcess(data, m, true);
}

static vector<unsigned char> doDecrypt(const vector<unsigned char>& data, const char* key) {
    unsigned char m[4];
    if (!invertMatrix((const unsigned char*)key, m)) {
        return {};
    }
    return hillProcess(data, m, false);
}

extern "C" {

const char* encrypt_text(const char* text, const char* key) {
    vector<unsigned char> input(text, text + strlen(text));
    g_resultString = bytesToHex(doEncrypt(input, key));
    return g_resultString.c_str();
}

const char* decrypt_text(const char* cipher, const char* key) {
    vector<unsigned char> data = hexToBytes(cipher);
    vector<unsigned char> plain = doDecrypt(data, key);
    g_resultString = string(plain.begin(), plain.end());
    return g_resultString.c_str();
}

unsigned char* encrypt_data(const unsigned char* data, int dataSize, const char* key, int* outSize) {
    vector<unsigned char> input(data, data + dataSize);
    g_resultData = doEncrypt(input, key);
    *outSize = (int)g_resultData.size();
    return g_resultData.data();
}

unsigned char* decrypt_data(const unsigned char* data, int dataSize, const char* key, int* outSize) {
    vector<unsigned char> input(data, data + dataSize);
    g_resultData = doDecrypt(input, key);
    *outSize = (int)g_resultData.size();
    return g_resultData.data();
}

const char* generate_key() {
    g_resultString = randomHill2x2Key();
    return g_resultString.c_str();
}

const char* get_key_hint() {
    return "Ключ: 4 символа, определитель матрицы должен быть нечётным";
}

int is_valid_key(const char* key) {
    if (!key || strlen(key) != 4) {
        return 0;
    }
    unsigned char m[4];
    memcpy(m, key, 4);
    return invMod(det2(m)) >= 0;
}

const char* get_algorithm_name() {
    return "Шифр Хилла (2x2)";
}

void free_memory(void* ptr) {}

}
