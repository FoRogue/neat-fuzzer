"""Эталонный фаззер: запускает обычный AFL++ (afl-fuzz) внутри Docker на заданное время
и переводит его статистику (plot_data, имена файлов крашей) в CSV:
afl_timeline.csv (время -> покрытие/краши/исполнения) и afl_crashes.csv (время каждого краша).

Запуск:  py -m neurofuzz.afl_baseline --target mini_maze --seconds 150
"""
from __future__ import annotations

import argparse
import csv
import subprocess
import time
from pathlib import Path

from .common import NO_ASLR, TARGETS, RunContext, build_targets, docker_run_cmd, run_logged

def afl_inner_command(target: str, seconds: int, out_rel: str) -> str:
    """bash-команда для контейнера: фаззинг в /tmp (быстрая ФС), затем прогон очереди через
    afl-showmap (docker/afl_replay.py) и копирование результатов в /work."""
    t = TARGETS[target]
    args = " ".join(t["args"])
    return (
        "export AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_NO_UI=1 "
        "AFL_NO_AFFINITY=1; "
        f"{NO_ASLR} afl-fuzz -i /work/{t['seeds']} -o /tmp/afl_out -V {seconds} -- {t['binary']} {args}; "
        "rc=$?; "
        f"mkdir -p /work/{out_rel} && "
        f"cp /tmp/afl_out/default/plot_data /tmp/afl_out/default/fuzzer_stats /work/{out_rel}/ && "
        f"{NO_ASLR} python3 /work/docker/afl_replay.py /tmp/afl_out/default {t['binary']} /work/{out_rel} {args}; "
        "exit $rc"
    )


def parse_plot_data(path: Path) -> list[dict]:
    """plot_data AFL++ -> список словарей (по заголовку из первой строки '# ...')."""
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    header = [h.strip() for h in lines[0].lstrip("#").split(",")]
    rows = []
    for line in lines[1:]:
        if not line.strip() or line.startswith("#"):
            continue
        vals = [v.strip() for v in line.split(",")]
        rows.append(dict(zip(header, vals)))
    return rows


def read_csv(path: Path) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def write_afl_csv(raw_dir: Path, out_dir: Path, seconds: float) -> tuple[Path, Path]:
    """Пишет afl_timeline.csv и afl_crashes.csv (колонки совпадают с CSV нейрофаззера).

    edges — число рёбер по afl-showmap для очереди AFL на момент времени (та же метрика,
    что у нейрофаззера); edges_afl — edges_found из plot_data (внутренний счётчик AFL).
    """
    replay = [(float(r["time_s"]), int(r["edges"])) for r in read_csv(raw_dir / "replay_timeline.csv")]
    crashes = [float(r["time_s"]) for r in read_csv(raw_dir / "crashes.csv")]
    plot = [(float(r["relative_time"]), r) for r in parse_plot_data(raw_dir / "plot_data")]
    times = sorted({0.0, float(seconds), *(t for t, _ in replay), *crashes, *(t for t, _ in plot)})
    timeline = out_dir / "afl_timeline.csv"
    with open(timeline, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["time_s", "edges", "unique_crashes", "total_execs", "edges_afl"])
        for t in times:
            edges = max([e for rt, e in replay if rt <= t], default=0)
            n_cr = sum(1 for ct in crashes if ct <= t)
            last = [r for pt, r in plot if pt <= t]
            execs = last[-1]["total_execs"] if last else ""
            e_afl = last[-1]["edges_found"] if last else ""
            w.writerow([round(t, 3), edges, n_cr, execs, e_afl])
    crash_csv = out_dir / "afl_crashes.csv"
    with open(crash_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["time_s", "crash_index", "file"])
        for r in read_csv(raw_dir / "crashes.csv"):
            w.writerow([r["time_s"], r["crash_index"], r["file"]])
    return timeline, crash_csv


def run_afl(ctx: RunContext, target: str, seconds: int, subdir: str = "afl") -> dict:
    """Запускает AFL++ и возвращает сводку. Сырые файлы AFL лежат в results/<run>/<subdir>/raw."""
    out_dir = ctx.results / subdir
    raw_rel = f"results/{ctx.name}/{subdir}/raw"
    cname = f"neurofuzz_afl_{ctx.name}".replace(":", "-")
    cmd = docker_run_cmd(afl_inner_command(target, seconds, raw_rel), name=cname)
    ctx.event("afl_start", target=target, seconds=seconds)
    t0 = time.time()
    try:
        run_logged(cmd, ctx, f"{subdir}_afl-fuzz.log", timeout=seconds + 300)
    except subprocess.TimeoutExpired:
        subprocess.run(["docker", "rm", "-f", cname], capture_output=True)
        raise
    timeline, crash_csv = write_afl_csv(out_dir / "raw", out_dir, seconds)
    stats = dict(line.split(":", 1) for line in
                 (out_dir / "raw" / "fuzzer_stats").read_text().splitlines() if ":" in line)
    stats = {k.strip(): v.strip() for k, v in stats.items()}
    summary = {"target": target, "seconds": seconds, "wall_s": round(time.time() - t0, 1),
               "edges_found": int(stats.get("edges_found", 0)),
               "edges_showmap": int(read_csv(timeline)[-1]["edges"]),
               "saved_crashes": int(stats.get("saved_crashes", 0)),
               "execs_done": int(stats.get("execs_done", 0)),
               "timeline_csv": str(timeline), "crashes_csv": str(crash_csv)}
    ctx.event("afl_finish", **summary)
    return summary


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--target", default="mini_maze", choices=sorted(TARGETS))
    ap.add_argument("--seconds", type=int, default=150)
    ap.add_argument("--no-build", action="store_true", help="не пересобирать мини-таргеты")
    a = ap.parse_args()
    ctx = RunContext.create("afl")
    ctx.save_config({"kind": "afl_baseline", **vars(a)})
    ctx.say(f"старт AFL++: таргет={a.target}, время={a.seconds}с, логи: {ctx.logs}")
    try:
        if not a.no_build and a.target.startswith("mini"):
            build_targets(ctx, "mini")
        s = run_afl(ctx, a.target, a.seconds)
        ctx.say(f"финиш: рёбер={s['edges_showmap']}, крашей={s['saved_crashes']}, "
                f"исполнений={s['execs_done']}; CSV: {ctx.results / 'afl'}")
    except Exception as e:
        ctx.log.exception("afl_baseline failed: %s", e)
        raise SystemExit(1)
    finally:
        ctx.close()


if __name__ == "__main__":
    main()
