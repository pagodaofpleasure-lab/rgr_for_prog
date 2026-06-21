# rgr_for_prog — РГЗ (динамические библиотеки)

Консольное приложение с загрузкой шифров из `.so` файлов.

## Состав команды

| Участник | Шифры |
|----------|-------|
| Ващенко А. А. | Speck, HIGHT |
| Ким Э. А. | RC4, шифр Хилла |
| Селякин Г. К. | RC5, XTEA |
| Лухнёв С. А. | AES, DES |

## Структура проекта

```
rgr_for_prog/
├── algorithm_interface.h   # общий интерфейс плагинов
├── utils.h                 # hex, PKCS7, ключи
├── library_loader.h/cpp    # загрузка .so через dlopen
├── main.cpp                # меню программы
├── speck_lib.cpp           # исходник плагина Speck
├── hight_lib.cpp
├── aes_lib.cpp
├── des_lib.cpp
├── rc4_lib.cpp
├── hill_lib.cpp
├── rc5_lib.cpp
├── xtea_lib.cpp
├── build.sh                # скрипт сборки
└── algorithms/             # сюда кладутся .so (создаётся при сборке)
```

## Сборка

```bash
cd rgr_for_prog
chmod +x build.sh
./build.sh
./app
```

Или вручную:

```bash
mkdir -p algorithms
g++ main.cpp library_loader.cpp -o app -ldl
g++ -shared -fPIC -o algorithms/speck.so speck_lib.cpp
g++ -shared -fPIC -o algorithms/hight.so hight_lib.cpp
g++ -shared -fPIC -o algorithms/aes.so aes_lib.cpp
g++ -shared -fPIC -o algorithms/des.so des_lib.cpp
g++ -shared -fPIC -o algorithms/rc4.so rc4_lib.cpp
g++ -shared -fPIC -o algorithms/hill.so hill_lib.cpp
g++ -shared -fPIC -o algorithms/rc5.so rc5_lib.cpp
g++ -shared -fPIC -o algorithms/xtea.so xtea_lib.cpp
```

## Как добавить свой шифр

1. Создайте файл `my_cipher_lib.cpp` в корне проекта.
2. Подключите `algorithm_interface.h` и реализуйте все функции с `extern "C"`.
3. Соберите плагин: `g++ -shared -fPIC -o algorithms/my_cipher.so my_cipher_lib.cpp`
4. Перезапустите `app` — шифр подхватится автоматически.

## Интерфейс плагина

Каждый `.so` должен экспортировать:

- `encrypt_text` / `decrypt_text` — работа с текстом (строковый ключ)
- `encrypt_data` / `decrypt_data` — работа с файлами
- `generate_key` — генерация ключа (строка)
- `get_key_hint` — подсказка о длине ключа
- `is_valid_key` — проверка ключа (1 = ок, 0 = нет)
- `get_algorithm_name` — имя в меню

## Требования к ключам

| Шифр | Ключ |
|------|------|
| Speck 128/128 | 16 символов |
| HIGHT | 1–16 символов (дополняется нулями) |
| AES-128 CBC | 16 символов |
| DES | 8 символов |
| RC4 | 1–256 символов |
| Hill (2×2) | 4 символа, определитель нечётный |
| RC5-32/12/16 | 1–16 символов (дополняется нулями) |
| XTEA | 16 символов |

## Примечания

- Программа ищет `.so` в папке `./algorithms/` при запуске.
- Для файлов: шифрование сохраняет результат в `файл.encrypted`, дешифрование убирает суффикс `.encrypted`.
- Блочные шифры в текстовом режиме выводят hex-строку.
