cmake_minimum_required(VERSION 3.16)
project(rgr_crypto CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(crypto_app
    src/main.cpp
    src/CipherRegistry.cpp
    src/utils/HexCodec.cpp
    ciphers/speck/SpeckCore.cpp
    ciphers/speck/SpeckCipher.cpp
    ciphers/hight/HightCore.cpp
    ciphers/hight/HightCipher.cpp
)

target_include_directories(crypto_app PRIVATE include ciphers)
