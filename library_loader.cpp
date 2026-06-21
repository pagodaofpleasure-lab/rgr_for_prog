// library_loader.cpp
// Компиляция: g++ -c library_loader.cpp

#include "library_loader.h"
#include <dlfcn.h>
#include <iostream>
#include <filesystem>

using namespace std;

LibraryLoader::LibraryLoader() {}

LibraryLoader::~LibraryLoader() {
    unloadAll();
}

bool LibraryLoader::loadAlgorithmsFromFolder(const string& folderPath) {
    namespace fs = filesystem;

    if (!fs::exists(folderPath) || !fs::is_directory(folderPath)) {
        cerr << "Ошибка: папка " << folderPath << " не существует" << endl;
        return false;
    }

    bool anyLoaded = false;

    for (const auto& entry : fs::directory_iterator(folderPath)) {
        string path = entry.path().string();
        if (path.length() > 3 && path.substr(path.length() - 3) == ".so") {
            cout << "Найдена библиотека: " << path << endl;
            if (loadLibrary(path)) {
                anyLoaded = true;
            }
        }
    }

    return anyLoaded;
}

bool LibraryLoader::loadLibrary(const string& filePath) {
    void* handle = dlopen(filePath.c_str(), RTLD_NOW);
    if (!handle) {
        cerr << "Не удалось загрузить " << filePath << ": " << dlerror() << endl;
        return false;
    }

    AlgorithmFunctions algo;
    algo.handle = handle;
    algo.filePath = filePath;

    if (!resolveFunctions(algo)) {
        dlclose(handle);
        return false;
    }

    algo.name = algo.get_algorithm_name();
    algorithms_.push_back(algo);

    cout << "Загружен алгоритм: " << algo.name << endl;
    return true;
}

bool LibraryLoader::resolveFunctions(AlgorithmFunctions& algo) {
    dlerror();

    algo.encrypt_text = (const char*(*)(const char*, const char*))
        dlsym(algo.handle, "encrypt_text");
    if (dlerror() != nullptr) {
        cerr << "Ошибка: не найдена функция encrypt_text" << endl;
        return false;
    }

    algo.decrypt_text = (const char*(*)(const char*, const char*))
        dlsym(algo.handle, "decrypt_text");
    if (dlerror() != nullptr) {
        cerr << "Ошибка: не найдена функция decrypt_text" << endl;
        return false;
    }

    algo.encrypt_data = (unsigned char*(*)(const unsigned char*, int, const char*, int*))
        dlsym(algo.handle, "encrypt_data");
    if (dlerror() != nullptr) {
        cerr << "Ошибка: не найдена функция encrypt_data" << endl;
        return false;
    }

    algo.decrypt_data = (unsigned char*(*)(const unsigned char*, int, const char*, int*))
        dlsym(algo.handle, "decrypt_data");
    if (dlerror() != nullptr) {
        cerr << "Ошибка: не найдена функция decrypt_data" << endl;
        return false;
    }

    algo.generate_key = (const char*(*)())
        dlsym(algo.handle, "generate_key");
    if (dlerror() != nullptr) {
        cerr << "Ошибка: не найдена функция generate_key" << endl;
        return false;
    }

    algo.get_key_hint = (const char*(*)())
        dlsym(algo.handle, "get_key_hint");
    if (dlerror() != nullptr) {
        cerr << "Ошибка: не найдена функция get_key_hint" << endl;
        return false;
    }

    algo.is_valid_key = (int(*)(const char*))
        dlsym(algo.handle, "is_valid_key");
    if (dlerror() != nullptr) {
        cerr << "Ошибка: не найдена функция is_valid_key" << endl;
        return false;
    }

    algo.get_algorithm_name = (const char*(*)())
        dlsym(algo.handle, "get_algorithm_name");
    if (dlerror() != nullptr) {
        cerr << "Ошибка: не найдена функция get_algorithm_name" << endl;
        return false;
    }

    algo.free_memory = (void(*)(void*))
        dlsym(algo.handle, "free_memory");

    return true;
}

const vector<AlgorithmFunctions>& LibraryLoader::getAlgorithms() const {
    return algorithms_;
}

void LibraryLoader::unloadAll() {
    for (auto& algo : algorithms_) {
        if (algo.handle) {
            dlclose(algo.handle);
        }
    }
    algorithms_.clear();
}
