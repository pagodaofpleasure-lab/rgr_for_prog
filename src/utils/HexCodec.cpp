#include "utils/HexCodec.h"

std::string bytesToHex(const std::vector<unsigned char>& data) {
    const char symbols[] = "0123456789abcdef";
    std::string result;

    for (size_t i = 0; i < data.size(); i++) {
        result += symbols[data[i] >> 4];
        result += symbols[data[i] & 0x0F];
    }

    return result;
}

std::vector<unsigned char> hexToBytes(const std::string& hex) {
    std::vector<unsigned char> result;

    if (hex.size() % 2 != 0) {
        return result;
    }

    for (size_t i = 0; i < hex.size(); i += 2) {
        int high = -1;
        int low = -1;
        char ch1 = hex[i];
        char ch2 = hex[i + 1];

        if (ch1 >= '0' && ch1 <= '9') high = ch1 - '0';
        else if (ch1 >= 'a' && ch1 <= 'f') high = ch1 - 'a' + 10;
        else if (ch1 >= 'A' && ch1 <= 'F') high = ch1 - 'A' + 10;

        if (ch2 >= '0' && ch2 <= '9') low = ch2 - '0';
        else if (ch2 >= 'a' && ch2 <= 'f') low = ch2 - 'a' + 10;
        else if (ch2 >= 'A' && ch2 <= 'F') low = ch2 - 'A' + 10;
        if (high < 0 || low < 0) {
            result.clear();
            return result;
        }
        result.push_back((unsigned char)((high << 4) | low));
    }

    return result;
}

void addPadding(std::vector<unsigned char>& data, int blockSize) {
    int padLen = blockSize - (data.size() % blockSize);
    for (int i = 0; i < padLen; i++) {
        data.push_back((unsigned char)padLen);
    }
}

bool removePadding(std::vector<unsigned char>& data, int blockSize) {
    if (data.empty() || data.size() % blockSize != 0) {
        return false;
    }

    unsigned char padLen = data.back();
    if (padLen < 1 || padLen > blockSize) {
        return false;
    }

    for (size_t i = data.size() - padLen; i < data.size(); i++) {
        if (data[i] != padLen) {
            return false;
        }
    }

    data.resize(data.size() - padLen);
    return true;
}
