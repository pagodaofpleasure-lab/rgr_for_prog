# rgr_for_prog — (РГЗ)

## Состав команды

 Участник | Шифры 

Ващенко А. А. | Speck, HIGHT 

Ким Э. А. | RC4, шифр Хилла 

Селякин Г. К. | RC5, XTEA 

Лухнёв С. А. | AES, DES 

## Сборка

```bash
cd rgr_for_prog
cmake -B build
cmake --build build
./build/crypto_app
```

## Как подключить свой шифр

1. Создайте папку `ciphers/<имя>/` (например, `ciphers/rc4/`).
2. Напишите класс, который наследует `ICipher` из `include/ICipher.h`.
3. Добавьте ваши `.cpp` файлы в `CMakeLists.txt`.
4. Добавьте одну строку в `src/CipherRegistry.cpp`:

```cpp
ciphers.push_back(std::make_unique<rc4::RC4Cipher>());
```

5. Не меняйте `main.cpp` и `ICipher.h` без согласования.

## Интерфейс ICipher

Каждый шифр реализует 6 методов:

- `getName()` — имя в меню
- `getKeyRequirementsInfo()` — подсказка о длине пароля
- `isValidKeyLength()` — проверка длины пароля
- `encryptText()` / `decryptText()` — работа с текстом
- `encryptFile()` / `decryptFile()` — работа с файлами

## Требования к паролю

| Шифр - Длина пароля |

Speck 128/128 - ровно 16 символов 

HIGHT - от 1 до 16 символов (дополняется нулями) 

RC4 -  

Hill -

RC5 -

XTEA -

AES - 

DES - 

## Структура проекта

```
rgr_for_prog/
├── include/
│   ├── ICipher.h           # общий интерфейс
│   ├── CipherRegistry.h
│   └── utils/HexCodec.h    # hex и padding для блочных шифров
├── src/
│   ├── main.cpp            # меню программы
│   └── CipherRegistry.cpp  # регистрация шифров
└── ciphers/
    ├── speck/              # готово
    ├── hight/              # готово
    ├── rc4/                # Ким
    ├── hill/               # Ким
    ├── rc5/                # Селякин
    ├── xtea/               # Селякин
    ├── aes/                # Лухнёв
    └── des/                # Лухнёв
```

## Примечания
