#include "CipherRegistry.h"

#include <memory>
#include <vector>

#include "hight/HightCipher.h"
#include "speck/SpeckCipher.h"

std::vector<std::unique_ptr<ICipher>> buildCipherRegistry() {
    std::vector<std::unique_ptr<ICipher>> ciphers;

    ciphers.push_back(std::make_unique<speck::SpeckCipher>());
    ciphers.push_back(std::make_unique<hight::HightCipher>());

    // Когда модуль готов — раскомментируйте свою строку:
    // ciphers.push_back(std::make_unique<rc4::RC4Cipher>());    // Ким
    // ciphers.push_back(std::make_unique<hill::HillCipher>());  // Ким
    // ciphers.push_back(std::make_unique<rc5::RC5Cipher>());    // Селякин
    // ciphers.push_back(std::make_unique<xtea::XTEACipher>());  // Селякин
    // ciphers.push_back(std::make_unique<aes::AESCipher>());    // Лухнёв
    // ciphers.push_back(std::make_unique<des::DESCipher>());    // Лухнёв

    return ciphers;
}
