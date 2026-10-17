#!/bin/bash
# Сборка таргета libpng из Magma (ВНУТРИ контейнера aflplusplus): клон libpng на коммите Magma,
# применение патчей Magma (возвращают 7 реальных багов PNG001..PNG007), сборка с AFL++ + ASAN.
# Результат: /work/build/libpng/libpng_read_fuzzer и сиды в /work/targets/libpng/seeds.
set -euo pipefail
MAGMA=/work/third_party/magma
SRC=/work/third_party/libpng_repo          # клон хранится в third_party, чтобы не качать заново
B=/tmp/libpng_build                         # собираем на быстрой ФС контейнера
OUT=/work/build/libpng
COMMIT=a37d4836519517bdce6cb9d956092321eca3e73b

mkdir -p /work/build
gcc -shared -fPIC -O2 -o /work/build/nocore.so /work/docker/nocore.c   # см. docker/nocore.c
if [ -x "$OUT/libpng_read_fuzzer" ] && [ "${FORCE:-0}" != 1 ]; then
  echo "libpng already built: $OUT/libpng_read_fuzzer"; exit 0
fi
if [ ! -d "$SRC/.git" ]; then
  git clone --no-checkout https://github.com/glennrp/libpng.git "$SRC"
fi
rm -rf "$B"; mkdir -p "$B" "$OUT"
git -C "$SRC" archive "$COMMIT" | tar -x -C "$B"

# Патчи Magma: %MAGMA_BUG% заменяется на имя бага (как в magma/apply_patches.sh)
for patch in "$MAGMA"/targets/libpng/patches/setup/*.patch "$MAGMA"/targets/libpng/patches/bugs/*.patch; do
  name=$(basename "$patch" .patch)
  # в образе нет утилиты patch — используем git apply
  # tr убирает CRLF, если Magma клонирована на Windows с autocrlf
  tr -d '\r' < "$patch" | sed "s/%MAGMA_BUG%/$name/g" | (cd "$B" && git apply -p1 --unidiff-zero --whitespace=nowarn -)
  echo "applied $name"
done

export CC=afl-clang-fast CXX=afl-clang-fast++ AFL_USE_ASAN=1 AFL_QUIET=1
export CFLAGS="-O1 -g" CXXFLAGS="-O1 -g"
cd "$B"
autoreconf -f -i >/dev/null 2>&1
./configure --with-libpng-prefix=MAGMA_ --disable-shared >/dev/null
make -j"$(nproc)" libpng16.la >/dev/null
# Без MAGMA_ENABLE_CANARIES: канарейки Magma не нужны, баг фиксируем по крашу ASAN.
$CXX $CXXFLAGS -std=c++11 -I. contrib/oss-fuzz/libpng_read_fuzzer.cc -o "$OUT/libpng_read_fuzzer" \
  .libs/libpng16.a /AFLplusplus/libAFLDriver.a -lz
mkdir -p /work/targets/libpng/seeds
cp "$MAGMA"/targets/libpng/corpus/libpng_read_fuzzer/* /work/targets/libpng/seeds/
echo "built $OUT/libpng_read_fuzzer"
