#!/bin/bash
# Сборка мини-таргетов с инструментацией AFL++ (запускается ВНУТРИ контейнера aflplusplus).
# Результат: /work/build/mini/<имя> — бинарники, которые понимают afl-fuzz и afl-showmap.
set -euo pipefail
mkdir -p /work/build/mini
for src in /work/targets/mini/*.c; do
  name=$(basename "$src" .c)
  AFL_QUIET=1 afl-clang-fast -O1 -g -o "/work/build/mini/$name" "$src"
  echo "built $name"
done
