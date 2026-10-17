#!/usr/bin/env python3
"""Запускается ВНУТРИ контейнера после afl-fuzz. Прогоняет все файлы очереди AFL через
afl-showmap и строит точную кривую «покрытие (число рёбер) от времени» той же метрикой,
что и нейрофаззер, плюс список крашей по времени. Пишет replay_timeline.csv и crashes.csv.
"""
import csv
import os
import re
import subprocess
import sys

out_dir, binary, dest = sys.argv[1], sys.argv[2], sys.argv[3]
args = sys.argv[4:]
TIME_RE = re.compile(r"time:(\d+)")


def t_of(name):
    m = TIME_RE.search(name)
    return int(m.group(1)) / 1000.0 if m else 0.0  # сиды без time: считаем временем 0


queue = os.path.join(out_dir, "queue")
maps = "/tmp/replay_maps"
os.makedirs(maps, exist_ok=True)
subprocess.run(["afl-showmap", "-q", "-i", queue, "-o", maps, "-t", "1000", "-m", "none", "--",
                binary] + args, check=False, env=dict(os.environ, AFL_CMIN_ALLOW_ANY="1"))
entries = sorted((t_of(n), n) for n in os.listdir(queue) if os.path.isfile(os.path.join(queue, n)))
seen = set()
os.makedirs(dest, exist_ok=True)
with open(os.path.join(dest, "replay_timeline.csv"), "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["time_s", "edges", "queue_file"])
    for t, n in entries:
        p = os.path.join(maps, n)
        if os.path.exists(p):
            with open(p) as mf:
                for line in mf:
                    if ":" in line:
                        seen.add(line.split(":", 1)[0])
        w.writerow([t, len(seen), n.replace(":", "_")])

crash_dir = os.path.join(out_dir, "crashes")
crashes = sorted((t_of(n), n) for n in os.listdir(crash_dir) if n.startswith("id"))
os.makedirs(os.path.join(dest, "crashes"), exist_ok=True)
with open(os.path.join(dest, "crashes.csv"), "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["time_s", "crash_index", "file"])
    for i, (t, n) in enumerate(crashes, 1):
        safe = n.replace(":", "_").replace(",", "_")
        with open(os.path.join(crash_dir, n), "rb") as src, open(os.path.join(dest, "crashes", safe), "wb") as d:
            d.write(src.read())
        w.writerow([t, i, safe])
