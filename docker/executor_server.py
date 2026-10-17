#!/usr/bin/env python3
"""Сервер исполнителя: живёт ВНУТРИ контейнера, получает по stdin пачки входов, прогоняет их
через afl-showmap (пакетный режим -i с forkserver — быстро) и возвращает по stdout для каждого
входа статус (0 ok / 1 таймаут / 2 краш) и карту покрытия (edge id -> класс счётчика AFL).

Протокол (little-endian): запрос  b'B' + u32 n + n * (u32 len + bytes);  b'Q' — выход.
                           ответ   u32 n + n * (u8 status + u32 k + k * (u32 edge, u8 cls)).
Запуск: python3 executor_server.py <timeout_ms> <binary> [args...]   (@@ = путь к входу)
"""
import os
import shutil
import struct
import subprocess
import sys

timeout_ms, binary, args = sys.argv[1], sys.argv[2], sys.argv[3:]
ROOT = "/fz" if os.path.isdir("/fz") else "/tmp/fz"   # /fz — tmpfs, монтируется клиентом
IN, OUT, ONE = ROOT + "/in", ROOT + "/out", ROOT + "/one"
SUS, SUS_OUT = ROOT + "/sus", ROOT + "/sus_out"
inp, outp = sys.stdin.buffer, sys.stdout.buffer
DEVNULL = subprocess.DEVNULL
# nocore.so отключает core dump таргета (в WSL2 каждый краш иначе вызывает внешний обработчик)
NOCORE = "/work/build/nocore.so"
ENV = dict(os.environ, AFL_PRELOAD=NOCORE) if os.path.exists(NOCORE) else dict(os.environ)


def read_exact(n):
    buf = b""
    while len(buf) < n:
        chunk = inp.read(n - len(buf))
        if not chunk:
            sys.exit(0)
        buf += chunk
    return buf


def parse_map(path, cmin):
    """Файл карты -> список (edge, cls). Обычный формат 'id:cls', формат -Z: 'id*1000+cls'."""
    res = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if cmin:
                v = int(line)
                res.append((v // 1000, v % 1000))
            else:
                a, b = line.split(":")
                res.append((int(a), int(b)))
    return res


def run_single(path):
    """Одиночный запуск: код возврата afl-showmap 0/1/2 = ok/таймаут/краш, карта пишется всегда."""
    if os.path.exists(ONE):
        os.remove(ONE)
    rc = subprocess.run(["afl-showmap", "-q", "-o", ONE, "-t", timeout_ms, "-m", "none", "--",
                         binary] + [path if a == "@@" else a for a in args],
                        stdout=DEVNULL, stderr=DEVNULL, env=ENV).returncode
    status = rc if rc in (0, 1, 2) else 2
    edges = parse_map(ONE, False) if os.path.exists(ONE) else []
    return status, edges


def run_batch(datas):
    for d in (IN, OUT):
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d)
    names = []
    for i, data in enumerate(datas):
        name = "%06d" % i
        with open(os.path.join(IN, name), "wb") as f:
            f.write(data)
        names.append(name)
    # -Z (режим afl-cmin): для крашей и таймаутов карта НЕ пишется -> по этому их и находим
    subprocess.run(["afl-showmap", "-q", "-Z", "-i", IN, "-o", OUT, "-t", timeout_ms, "-m", "none",
                    "--", binary] + args, stdout=DEVNULL, stderr=DEVNULL, env=ENV)
    maps = {}
    suspects = []
    for name in names:
        mp = os.path.join(OUT, name)
        edges = parse_map(mp, True) if os.path.exists(mp) else []
        if edges:
            maps[name] = (0, edges)
        else:
            # Краш/таймаут: в режиме -Z карта не создаётся или пуста (нормальный запуск всегда
            # даёт хотя бы одно ребро).
            suspects.append(name)
    if suspects:
        # Второй проход одним вызовом: AFL_CMIN_CRASHES_ONLY=1 пишет карты ТОЛЬКО для крашей.
        # Так много одинаковых крашей не стоят по одиночному запуску afl-showmap каждый.
        for d in (SUS, SUS_OUT):
            shutil.rmtree(d, ignore_errors=True)
            os.makedirs(d)
        for name in suspects:
            os.rename(os.path.join(IN, name), os.path.join(SUS, name))
        subprocess.run(["afl-showmap", "-q", "-Z", "-i", SUS, "-o", SUS_OUT, "-t", timeout_ms, "-m", "none",
                        "--", binary] + args, stdout=DEVNULL, stderr=DEVNULL,
                       env=dict(ENV, AFL_CMIN_CRASHES_ONLY="1"))
        for name in suspects:
            mp = os.path.join(SUS_OUT, name)
            if os.path.exists(mp):
                maps[name] = (2, parse_map(mp, True))
            else:  # не краш -> скорее всего таймаут; уточняем одиночным запуском (редко)
                maps[name] = run_single(os.path.join(SUS, name))
    return [maps[n] for n in names]


def main():
    os.makedirs(ROOT, exist_ok=True)
    outp.write(b"READY\n")
    outp.flush()
    while True:
        op = read_exact(1)
        if op == b"Q":
            return
        (n,) = struct.unpack("<I", read_exact(4))
        datas = []
        for _ in range(n):
            (ln,) = struct.unpack("<I", read_exact(4))
            datas.append(read_exact(ln))
        res = run_batch(datas)
        parts = [struct.pack("<I", len(res))]
        for status, edges in res:
            parts.append(struct.pack("<BI", status, len(edges)))
            parts.append(b"".join(struct.pack("<IB", e, min(c, 255)) for e, c in edges))
        outp.write(b"".join(parts))
        outp.flush()


if __name__ == "__main__":
    main()
