#!/bin/bash
# Сборка мини-таргетов с инструментацией AFL++ (запускается ВНУТРИ контейнера aflplusplus).
# Результат: /work/build/mini/<имя>. -O0 + AFL_DONT_OPTIMIZE=1 (afl-cc иначе сам добавляет -O3): без этого
# clang склеивает побайтовые проверки магии в одну ветку и «лабиринт» становится плоским.
set -euo pipefail
mkdir -p /work/build/mini
for src in /work/targets/mini/*.c; do
  name=$(basename "$src" .c)
  AFL_QUIET=1 AFL_DONT_OPTIMIZE=1 afl-clang-fast -O0 -g -o "/work/build/mini/$name" "$src"
  echo "built $name"
done
# nocore.so — см. docker/nocore.c (ускоряет обработку крашей в WSL2 в десятки раз)
gcc -shared -fPIC -O2 -o /work/build/nocore.so /work/docker/nocore.c
echo "built nocore.so"
