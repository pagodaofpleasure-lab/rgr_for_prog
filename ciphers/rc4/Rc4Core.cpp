#include "Rc4Core.h"

namespace rc4 {

static const size_t kSboxSize = 256;

void ksaInit(const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv, std::vector<unsigned char>& sBox) {
    sBox.resize(kSboxSize);
    for (size_t i = 0; i < kSboxSize; ++i) {
        sBox[i] = (unsigned char)i;
    }

    std::vector<unsigned char> fullKey = key;
    fullKey.insert(fullKey.end(), iv.begin(), iv.end());

    size_t j = 0;
    for (size_t i = 0; i < kSboxSize; ++i) {
        j = (j + sBox[i] + fullKey[i % fullKey.size()]) % kSboxSize;
        std::swap(sBox[i], sBox[j]);
    }
}

std::vector<unsigned char> crypt(const std::vector<unsigned char>& data, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv) {
    std::vector<unsigned char> sBox;
    ksaInit(key, iv, sBox);

    std::vector<unsigned char> result;
    result.reserve(data.size());

    size_t i = 0;
    size_t j = 0;

    for (size_t k = 0; k < data.size(); ++k) {
        i = (i + 1) % kSboxSize;
        j = (j + sBox[i]) % kSboxSize;
        std::swap(sBox[i], sBox[j]);

        unsigned char keystreamByte = sBox[(sBox[i] + sBox[j]) % kSboxSize];
        result.push_back((unsigned char)(data[k] ^ keystreamByte));
    }

    return result;
}

} // namespace rc4
