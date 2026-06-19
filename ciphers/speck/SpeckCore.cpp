#include "SpeckCore.h"

#include <cstring>

namespace speck {

static uint64_t ror64(uint64_t x, int r) {
    return (x >> r) | (x << (64 - r));
}

static uint64_t rol64(uint64_t x, int r) {
    return (x << r) | (x >> (64 - r));
}

// Один раунд Speck (ARX: add-rotate-xor)
static void roundForward(uint64_t& x, uint64_t& y, uint64_t k) {
    x = ror64(x, 8);
    x += y;
    x ^= k;
    y = rol64(y, 3);
    y ^= x;
}

static void roundBackward(uint64_t& x, uint64_t& y, uint64_t k) {
    y ^= x;
    y = ror64(y, 3);
    x ^= k;
    x -= y;
    x = rol64(x, 8);
}

// Эталонная реализация Speck 128/128 (32 раунда, ключ 128 бит)
void encryptBlock(const unsigned char* plaintext, unsigned char* ciphertext, const unsigned char* key) {
    uint64_t y, x, b, a;

    std::memcpy(&y, plaintext, 8);
    std::memcpy(&x, plaintext + 8, 8);
    std::memcpy(&b, key, 8);
    std::memcpy(&a, key + 8, 8);

    roundForward(x, y, b);
    for (int i = 0; i < kRounds - 1; i++) {
        roundForward(a, b, (uint64_t)i);
        roundForward(x, y, b);
    }

    std::memcpy(ciphertext, &y, 8);
    std::memcpy(ciphertext + 8, &x, 8);
}

void decryptBlock(const unsigned char* ciphertext, unsigned char* plaintext, const unsigned char* key) {
    uint64_t y, x, b, a;
    uint64_t roundKeys[kRounds];

    std::memcpy(&y, ciphertext, 8);
    std::memcpy(&x, ciphertext + 8, 8);
    std::memcpy(&b, key, 8);
    std::memcpy(&a, key + 8, 8);

    roundKeys[0] = b;
    for (int i = 0; i < kRounds - 1; i++) {
        roundForward(a, b, (uint64_t)i);
        roundKeys[i + 1] = b;
    }

    for (int i = kRounds - 1; i > 0; i--) {
        roundBackward(x, y, roundKeys[i]);
    }
    roundBackward(x, y, roundKeys[0]);

    std::memcpy(plaintext, &y, 8);
    std::memcpy(plaintext + 8, &x, 8);
}

} // namespace speck
