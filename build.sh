#!/bin/bash
# Сборка приложения и всех плагинов

set -e
mkdir -p algorithms

echo "Сборка app..."
g++ main.cpp library_loader.cpp -o app -ldl

LIBS="speck hight aes des rc4 hill rc5 xtea"
for name in $LIBS; do
    echo "Сборка algorithms/${name}.so..."
    g++ -shared -fPIC -o "algorithms/${name}.so" "${name}_lib.cpp"
done

echo "Готово. Запуск: ./app"
