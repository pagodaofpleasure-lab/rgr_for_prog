// algorithm_interface.h
// Общий интерфейс для всех плагинов шифрования (.so)

#ifndef ALGORITHM_INTERFACE_H
#define ALGORITHM_INTERFACE_H

extern "C" {

const char* encrypt_text(const char* text, const char* key);
const char* decrypt_text(const char* cipher, const char* key);
unsigned char* encrypt_data(const unsigned char* data, int dataSize, const char* key, int* outSize);
unsigned char* decrypt_data(const unsigned char* data, int dataSize, const char* key, int* outSize);
const char* generate_key();
const char* get_key_hint();
int is_valid_key(const char* key);
const char* get_algorithm_name();
void free_memory(void* ptr);

}

#endif
