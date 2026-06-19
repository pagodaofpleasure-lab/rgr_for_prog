#pragma once

#include <string>
#include <vector>

// Простое преобразование байтов в hex-строку и обратно (для текстового режима)
std::string bytesToHex(const std::vector<unsigned char>& data);
std::vector<unsigned char> hexToBytes(const std::string& hex);

// PKCS7: дополнение и удаление (для блочных шифров)
void addPadding(std::vector<unsigned char>& data, int blockSize);
bool removePadding(std::vector<unsigned char>& data, int blockSize);
