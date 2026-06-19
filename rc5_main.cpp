#include <iostream>
#include <fstream>
#include "rc5.h"

using namespace std;

int main() {
    vector<uint8_t> key = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10};
    vector<uint8_t> iv = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22};

    RC5 cipher(key);

    ofstream out("test.txt");
    out << "Проверка Проверка С.Г";
    out.close();

    if (encryptFile(cipher, "test.txt", "encrypted.dat", iv)) {
        cout << "Файл успешно зашифрован!" << endl;
    }

    if (decryptFile(cipher, "encrypted.dat", "restored.txt", iv)) {
        cout << "Файл успешно восстановлен в restored.txt!" << endl;
    }

    return 0;
}