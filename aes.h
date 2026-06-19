#ifndef AES_H
#define AES_H

#include <vector>
#include <cstdint>

class AES {
public:
    AES(const std::vector<uint8_t>& key);
    void encrypt(const uint8_t* input, uint8_t* output);
    void decrypt(const uint8_t* input, uint8_t* output);

private:
    uint8_t round_keys[176];
    static const uint8_t sbox[256];
    static const uint8_t rsbox[256];

    void key_expansion(const uint8_t* key);
    void sub_bytes(uint8_t* state);
    void inv_sub_bytes(uint8_t* state);
    void shift_rows(uint8_t* state);
    void inv_shift_rows(uint8_t* state);
    void mix_columns(uint8_t* state);
    void inv_mix_columns(uint8_t* state);
    void add_round_key(uint8_t* state, const uint8_t* key);
};

#endif
