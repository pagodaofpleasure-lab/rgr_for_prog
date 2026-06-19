#pragma once

#include <cstddef>
#include <vector>

namespace rc4 {

const int kIvSize = 16;
const int kMaxKeySize = 256;

void ksaInit(const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv, std::vector<unsigned char>& sBox);
std::vector<unsigned char> crypt(const std::vector<unsigned char>& data, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv);

} // namespace rc4
