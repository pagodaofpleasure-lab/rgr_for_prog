// utils.h
// Простые вспомогательные функции для шифров

#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cstdlib>
#include <ctime>

inline std::string bytesToHex(const std::vector<unsigned char>& data) {
    std::ostringstream oss;
    for (unsigned char b : data) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    }
    return oss.str();
}

inline std::vector<unsigned char> hexToBytes(const std::string& hex) {
    std::vector<unsigned char> out;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        unsigned int v = 0;
        std::istringstream iss(hex.substr(i, 2));
        iss >> std::hex >> v;
        out.push_back((unsigned char)v);
    }
    return out;
}

inline std::vector<unsigned char> pkcs7Pad(const std::vector<unsigned char>& data, size_t blockSize) {
    size_t pad = blockSize - (data.size() % blockSize);
    if (pad == 0) {
        pad = blockSize;
    }
    std::vector<unsigned char> out = data;
    for (size_t i = 0; i < pad; ++i) {
        out.push_back((unsigned char)pad);
    }
    return out;
}

inline std::vector<unsigned char> pkcs7Unpad(const std::vector<unsigned char>& data) {
    if (data.empty()) {
        return {};
    }
    unsigned char pad = data.back();
    if (pad == 0 || pad > data.size()) {
        return {};
    }
    return std::vector<unsigned char>(data.begin(), data.end() - pad);
}

inline void copyKey(const char* key, unsigned char* out, size_t len) {
    size_t keyLen = key ? strlen(key) : 0;
    for (size_t i = 0; i < len; ++i) {
        out[i] = (i < keyLen) ? (unsigned char)key[i] : 0;
    }
}

inline void randomBytes(unsigned char* buf, int n) {
    static bool seeded = false;
    if (!seeded) {
        srand((unsigned)time(nullptr));
        seeded = true;
    }
    for (int i = 0; i < n; ++i) {
        buf[i] = (unsigned char)(rand() % 256);
    }
}

inline std::string randomKeyString(int len) {
    std::string s;
    s.resize(len);
    for (int i = 0; i < len; ++i) {
        s[i] = (char)('a' + (rand() % 26));
    }
    return s;
}

inline std::string randomHill2x2Key() {
    static bool seeded = false;
    if (!seeded) {
        srand((unsigned)time(nullptr));
        seeded = true;
    }
    
    std::string key;
    key.resize(4);
    
    while (true) {
        for (int i = 0; i < 4; ++i) {
            key[i] = static_cast<char>(33 + (rand() % 93));
        }
        int a = static_cast<unsigned char>(key[0]);
        int b = static_cast<unsigned char>(key[1]);
        int c = static_cast<unsigned char>(key[2]);
        int d = static_cast<unsigned char>(key[3]);
        
        int det = (a * d - b * c) % 256;
        if (det < 0) det += 256;
        
        if (det % 2 != 0) {
            return key;
        }
    }
}

#endif
