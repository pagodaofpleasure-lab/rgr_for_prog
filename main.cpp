#include <iostream>
#include <string>
#include <vector>
#include <limits>
#include <stdexcept>
#include <clocale>
#include <fstream>
#include <filesystem>
#include "library_loader.h"
using namespace std;

static LibraryLoader g_loader;
static const vector<AlgorithmFunctions>* g_algorithms = nullptr;
static int g_currentAlgorithm = -1;

string getCurrentAlgorithmName() {
    if (!g_algorithms || g_currentAlgorithm < 0 || g_currentAlgorithm >= (int)g_algorithms->size()) {
        return "Не выбран";
    }
    return (*g_algorithms)[g_currentAlgorithm].name;
}

string getCurrentKeyHint() {
    if (!g_algorithms || g_currentAlgorithm < 0) {
        return "";
    }
    return (*g_algorithms)[g_currentAlgorithm].get_key_hint();
}

string encryptText(const string& text, const string& key) {
    if (!g_algorithms || g_currentAlgorithm < 0) {
        throw runtime_error("Алгоритм не выбран");
    }
    const char* result = (*g_algorithms)[g_currentAlgorithm].encrypt_text(text.c_str(), key.c_str());
    return string(result);
}

string decryptText(const string& text, const string& key) {
    if (!g_algorithms || g_currentAlgorithm < 0) {
        throw runtime_error("Алгоритм не выбран");
    }
    const char* result = (*g_algorithms)[g_currentAlgorithm].decrypt_text(text.c_str(), key.c_str());
    return string(result);
}

vector<unsigned char> encryptData(const vector<unsigned char>& data, const string& key) {
    if (!g_algorithms || g_currentAlgorithm < 0) {
        throw runtime_error("Алгоритм не выбран");
    }
    int outSize = 0;
    unsigned char* result = (*g_algorithms)[g_currentAlgorithm].encrypt_data(
        data.data(), (int)data.size(), key.c_str(), &outSize
    );
    if (!result || outSize <= 0) {
        throw runtime_error("Ошибка шифрования данных");
    }
    return vector<unsigned char>(result, result + outSize);
}

vector<unsigned char> decryptData(const vector<unsigned char>& data, const string& key) {
    if (!g_algorithms || g_currentAlgorithm < 0) {
        throw runtime_error("Алгоритм не выбран");
    }
    int outSize = 0;
    unsigned char* result = (*g_algorithms)[g_currentAlgorithm].decrypt_data(
        data.data(), (int)data.size(), key.c_str(), &outSize
    );
    if (!result || outSize <= 0) {
        throw runtime_error("Ошибка дешифрования данных");
    }
    return vector<unsigned char>(result, result + outSize);
}

string generateKey() {
    if (!g_algorithms || g_currentAlgorithm < 0) {
        throw runtime_error("Алгоритм не выбран");
    }
    return (*g_algorithms)[g_currentAlgorithm].generate_key();
}

bool isValidKey(const string& key) {
    if (!g_algorithms || g_currentAlgorithm < 0) {
        return false;
    }
    return (*g_algorithms)[g_currentAlgorithm].is_valid_key(key.c_str()) != 0;
}

void clearInputStream() {
    cin.clear();
    cin.ignore(numeric_limits<streamsize>::max(), '\n');
}

void waitForEnter() {
    cout << endl << "Нажмите Enter для продолжения";
    cin.ignore(numeric_limits<streamsize>::max(), '\n');
    cout << endl;
}

void showError(const string& message) {
    cerr << endl << "[ОШИБКА] " << message << endl;
}

string readKeyFromUser() {
    string hint = getCurrentKeyHint();
    if (!hint.empty()) {
        cout << "Подсказка: " << hint << endl;
    }

    while (true) {
        cout << "Введите ключ или оставьте пустым для генерации: ";
        string keyInput;
        getline(cin, keyInput);

        if (keyInput.empty()) {
            string key = generateKey();
            cout << "Сгенерированный ключ: " << key << endl;
            return key;
        }

        if (isValidKey(keyInput)) {
            return keyInput;
        }

        cout << "Ошибка: неверный ключ. Попробуйте снова." << endl;
    }
}

void processTextOperation() {
    cout << endl << "РАБОТА С ТЕКСТОМ" << endl;
    cout << "Текуший алгоритм: " << getCurrentAlgorithmName() << endl;
    cout << "Выберите действие:" << endl;
    cout << "1. Зашифровать текст" << endl;
    cout << "2. Расшифровать текст" << endl;

    int choice = 0;
    while (choice == 0) {
        cout << "Ваш выбор: ";
        string choiceStr;
        getline(cin, choiceStr);

        if (choiceStr.empty()) {
            cout << "Ошибка: введите число 1 или 2." << endl;
            continue;
        }

        try {
            int tmp = stoi(choiceStr);
            if (tmp != 1 && tmp != 2) {
                cout << "Ошибка: Введите 1 или 2." << endl;
                continue;
            }
            choice = tmp;
        } catch (const exception&) {
            cout << "Ошибка: введите число 1 или 2." << endl;
        }
    }

    string text;
    do {
        cout << "Введите текст: ";
        getline(cin, text);
        if (text.empty()) {
            cout << "Ошибка: текст не может быть пустым, попробуйте снова." << endl;
        }
    } while (text.empty());

    string key = readKeyFromUser();

    try {
        string result;
        if (choice == 1) {
            result = encryptText(text, key);
            cout << endl << "ЗАШИФРОВАННЫЙ ТЕКСТ" << endl;
        } else {
            result = decryptText(text, key);
            cout << endl << "РАСШИФРОВАННЫЙ ТЕКСТ" << endl;
        }

        if (result.length() <= 100) {
            cout << result << endl;
        } else {
            cout << "Результат слишком длинный (" << result.length() << " символов)." << endl;
            cout << "Первые 100 символов:" << endl;
            cout << result.substr(0, 100) << "..." << endl;
        }
    } catch (const exception& e) {
        cout << "Ошибка при выполнении операции: " << e.what() << endl;
    }

    waitForEnter();
}

void processFileOperation() {
    cout << endl << "РАБОТА С ФАЙЛОМ" << endl;
    cout << "Текущий алгоритм: " << getCurrentAlgorithmName() << endl;
    cout << "Выберите действие:" << endl;
    cout << "1. Зашифровать файл" << endl;
    cout << "2. Расшифровать файл" << endl;

    int choice = 0;
    while (choice == 0) {
        cout << "Ваш выбор: ";
        string choiceStr;
        getline(cin, choiceStr);

        if (choiceStr.empty()) {
            cout << "Ошибка: введите число 1 или 2." << endl;
            continue;
        }

        try {
            int tmp = stoi(choiceStr);
            if (tmp != 1 && tmp != 2) {
                cout << "Ошибка: Введите 1 или 2." << endl;
                continue;
            }
            choice = tmp;
        } catch (const exception&) {
            cout << "Ошибка: введите число 1 или 2." << endl;
        }
    }

    string key = readKeyFromUser();

    cout << endl << "Введите путь к файлу: ";
    string filePath;
    getline(cin, filePath);

    if (filePath.empty()) {
        cout << "Ошибка: путь к файлу не может быть пустым." << endl;
        waitForEnter();
        return;
    }

    if (!filesystem::exists(filePath)) {
        cout << "Файл не существует: " << filePath << endl;
        cout << "Создать пустой файл? (y/n): ";
        string answer;
        getline(cin, answer);

        if (answer == "y" || answer == "Y") {
            filesystem::path path(filePath);
            filesystem::path parent = path.parent_path();
            if (!parent.empty() && !filesystem::exists(parent)) {
                filesystem::create_directories(parent);
            }
            ofstream newFile(filePath, ios::binary);
            if (!newFile.is_open()) {
                cout << "Ошибка: не удалось создать файл." << endl;
                waitForEnter();
                return;
            }
            newFile.close();
        } else {
            waitForEnter();
            return;
        }
    }

    ifstream inputFile(filePath, ios::binary);
    if (!inputFile.is_open()) {
        cout << "Ошибка: не удалось открыть файл." << endl;
        waitForEnter();
        return;
    }

    vector<unsigned char> data((istreambuf_iterator<char>(inputFile)), istreambuf_iterator<char>());
    inputFile.close();

    if (data.empty()) {
        cout << "Ошибка: файл пуст." << endl;
        waitForEnter();
        return;
    }

    cout << "Размер файла: " << data.size() << " байт" << endl;

    try {
        vector<unsigned char> result;
        if (choice == 1) {
            result = encryptData(data, key);
        } else {
            result = decryptData(data, key);
        }

        string outputPath;
        if (choice == 1) {
            outputPath = filePath + ".encrypted";
        } else if (filePath.length() > 10 && filePath.substr(filePath.length() - 10) == ".encrypted") {
            outputPath = filePath.substr(0, filePath.length() - 10);
        } else {
            outputPath = filePath + ".decrypted";
        }

        ofstream outputFile(outputPath, ios::binary);
        if (!outputFile.is_open()) {
            cout << "Ошибка: не удалось создать файл результата." << endl;
            waitForEnter();
            return;
        }

        outputFile.write(reinterpret_cast<char*>(result.data()), result.size());
        outputFile.close();

        cout << "Результат сохранён в: " << outputPath << endl;
    } catch (const exception& e) {
        cout << "Ошибка при выполнении операции: " << e.what() << endl;
    }

    waitForEnter();
}

void selectAlgorithm() {
    try {
        cout << endl << "ВЫБОР АЛГОРИТМА" << endl;

        if (!g_algorithms || g_algorithms->empty()) {
            throw runtime_error("Нет загруженных алгоритмов.");
        }

        for (size_t i = 0; i < g_algorithms->size(); ++i) {
            cout << (i + 1) << ". " << (*g_algorithms)[i].name << endl;
        }

        int choice = 0;
        while (choice == 0) {
            cout << "Выберите алгоритм (1-" << g_algorithms->size() << "): ";
            string choiceStr;
            getline(cin, choiceStr);

            if (choiceStr.empty()) {
                cout << "Ошибка: введите число." << endl;
                continue;
            }

            try {
                int tmp = stoi(choiceStr);
                if (tmp < 1 || tmp > (int)g_algorithms->size()) {
                    cout << "Ошибка: неверный выбор." << endl;
                    continue;
                }
                choice = tmp;
            } catch (const exception&) {
                cout << "Ошибка: введите число." << endl;
            }
        }

        g_currentAlgorithm = choice - 1;
        cout << endl << "Выбран алгоритм: " << getCurrentAlgorithmName() << endl;
        waitForEnter();
    } catch (const exception& e) {
        showError(e.what());
        waitForEnter();
    }
}

void showMainMenu() {
    cout << endl;
    cout << "Encryption program" << endl;
    cout << endl;
    cout << "Выбранный алгоритм: " << getCurrentAlgorithmName() << endl;
    cout << endl;
    cout << "1. Шифрование/дешифрование ТЕКСТА" << endl;
    cout << "2. Шифрование/дешифрование ФАЙЛА" << endl;
    cout << "3. Выбрать алгоритм" << endl;
    cout << "4. Выход" << endl;
    cout << endl;
    cout << "Ваш выбор: ";
}

int main() {
    setlocale(LC_ALL, "Russian");

    cout << "Добро пожаловать!" << endl;
    cout << "Загрузка алгоритмов из папки algorithms/..." << endl;

    if (!filesystem::exists("./algorithms")) {
        filesystem::create_directory("./algorithms");
        cout << "Создана папка ./algorithms" << endl;
        cout << "Соберите .so файлы и перезапустите программу." << endl;
        return 0;
    }

    if (!g_loader.loadAlgorithmsFromFolder("./algorithms")) {
        cout << "Не удалось загрузить алгоритмы." << endl;
        cout << "Поместите .so файлы в папку 'algorithms/' и перезапустите программу." << endl;
        return 1;
    }

    g_algorithms = &g_loader.getAlgorithms();

    if (g_algorithms->empty()) {
        cout << "Нет загруженных алгоритмов. Завершение работы." << endl;
        return 1;
    }

    cout << "Загружено алгоритмов: " << g_algorithms->size() << endl;
    g_currentAlgorithm = 0;
    cout << "Выбран алгоритм по умолчанию: " << getCurrentAlgorithmName() << endl;

    bool running = true;
    while (running) {
        showMainMenu();

        string choiceStr;
        getline(cin, choiceStr);

        if (choiceStr.empty()) {
            showError("Введите число от 1 до 4.");
            waitForEnter();
            continue;
        }

        int choice;
        try {
            choice = stoi(choiceStr);
        } catch (const exception&) {
            showError("Введите число от 1 до 4.");
            waitForEnter();
            continue;
        }

        if (choice < 1 || choice > 4) {
            showError("Неверный выбор. Введите число от 1 до 4.");
            waitForEnter();
            continue;
        }

        if (choice == 1) {
            processTextOperation();
        } else if (choice == 2) {
            processFileOperation();
        } else if (choice == 3) {
            selectAlgorithm();
        } else if (choice == 4) {
            cout << endl << "Завершение работы программы." << endl;
            running = false;
        }
    }

    return 0;
}
