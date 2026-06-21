// library_loader.h
// Загрузчик динамических библиотек (.so)

#ifndef LIBRARY_LOADER_H
#define LIBRARY_LOADER_H

#include <string>
#include <vector>
using namespace std;

struct AlgorithmFunctions {
    void* handle;

    const char* (*encrypt_text)(const char*, const char*);
    const char* (*decrypt_text)(const char*, const char*);
    unsigned char* (*encrypt_data)(const unsigned char*, int, const char*, int*);
    unsigned char* (*decrypt_data)(const unsigned char*, int, const char*, int*);
    const char* (*generate_key)();
    const char* (*get_key_hint)();
    int (*is_valid_key)(const char*);
    const char* (*get_algorithm_name)();
    void (*free_memory)(void*);

    string name;
    string filePath;
};

class LibraryLoader {
public:
    LibraryLoader();
    ~LibraryLoader();

    bool loadAlgorithmsFromFolder(const string& folderPath);
    const vector<AlgorithmFunctions>& getAlgorithms() const;
    void unloadAll();

private:
    vector<AlgorithmFunctions> algorithms_;

    bool loadLibrary(const string& filePath);
    bool resolveFunctions(AlgorithmFunctions& algo);
};

#endif
