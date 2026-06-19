#include <iostream>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include "CipherRegistry.h"
#include "ICipher.h"

void clearInput() {
    std::cin.clear();
    std::cin.ignore(10000, '\n');
}

bool fileExists(const std::string& path) {
    std::ifstream file(path.c_str(), std::ios::binary);
    return file.good();
}

int main() {
    std::vector<std::unique_ptr<ICipher>> ciphers = buildCipherRegistry();

    while (true) {
        std::cout << "\nПРОГРАММА ШИФРОВАНИЯ\n";
        std::cout << "1. Зашифровать текст\n";
        std::cout << "2. Расшифровать текст\n";
        std::cout << "3. Зашифровать файл\n";
        std::cout << "4. Расшифровать файл\n";
        std::cout << "5. Выход\n";
        std::cout << "Выберите действие: ";

        int choice = 0;
        if (!(std::cin >> choice)) {
            clearInput();
            std::cout << "Ошибка: Некорректный ввод.\n";
            continue;
        }
        clearInput();

        if (choice == 5) {
            std::cout << "Программа завершила работу\n";
            break;
        }

        if (choice < 1 || choice > 4) {
            std::cout <<"Ошибка: Неверный выбор попробуйте снова.\n";
            continue;
        }

        bool encrypt = (choice == 1 || choice == 3);
        bool isText = (choice == 1 || choice == 2);

        if (ciphers.empty()) {
            std::cout << "Нет зарегистрированных шифров.\n";
            continue;
        }

        std::cout << "\nВыберите алгоритм\n";
        for (size_t i = 0; i < ciphers.size(); i++) {
            std::cout << i + 1 << ". " << ciphers[i]->getName() << "\n";
        }
        std::cout << "Выбор: ";

        int cipherChoice = 0;
        if (!(std::cin >> cipherChoice) || cipherChoice < 1 || cipherChoice > (int)ciphers.size()) {
            clearInput();
            std::cout << "[!] Неверный выбор алгоритма.\n";
            continue;
        }
        clearInput();

        ICipher* cipher = ciphers[cipherChoice - 1].get();
        std::cout << "[+] Выбран: " << cipher->getName() << "\n";

        std::string inputText;
        std::string inputPath;
        std::string outputPath;

        if (isText) {
            std::cout << "Введите текст:\n> ";
            std::getline(std::cin, inputText);
        } else {
            while (true) {
                std::cout << "Введите путь к файлу: ";
                std::getline(std::cin, inputPath);

                if (!fileExists(inputPath)) {
                    std::cout << "[!] Файл не найден. Попробуйте снова.\n";
                    continue;
                }
                break;
            }

            std::cout << "Введите путь для сохранения результата: ";
            std::getline(std::cin, outputPath);

            if (inputPath == outputPath) {
                std::cout << "[!] Пути источника и назначения должны отличаться.\n";
                continue;
            }
        }

        // Ввод пароля
        std::string password;
        while (true) {
            std::cout << "Введите пароль (" << cipher->getKeyRequirementsInfo() << "): ";
            std::getline(std::cin, password);

            if (!cipher->isValidKeyLength(password.length())) {
                std::cout << "[!] Неверная длина пароля.\n";
                continue;
            }
            break;
        }

        // Выполнение операции
        if (isText) {
            std::string result;
            if (encrypt) {
                result = cipher->encryptText(inputText, password);
            } else {
                result = cipher->decryptText(inputText, password);
            }
            std::cout << "\n--- РЕЗУЛЬТАТ ---\n" << result << "\n-----------------\n";
        } else {
            bool ok = false;
            if (encrypt) {
                ok = cipher->encryptFile(inputPath, outputPath, password);
            } else {
                ok = cipher->decryptFile(inputPath, outputPath, password);
            }

            if (ok) {
                std::cout << "[+] Готово: " << outputPath << "\n";
            } else {
                std::cout << "[!] Ошибка при обработке файла.\n";
            }
        }
    }

    return 0;
}
