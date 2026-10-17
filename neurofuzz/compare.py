"""Сравнение фаззеров на одном таргете за одинаковое время: AFL++, нейрофаззер (NEAT) и
случайный фаззер запускаются ПО ОЧЕРЕДИ (чтобы не делить процессор), каждый — на --seconds.
Результат: results/<run>/{afl,neat,random}/..., сводка comparison_summary.csv и графики SVG.

Запуск:  py -m neurofuzz.compare --target mini_maze --seconds 300
"""
from __future__ import annotations

import argparse
import csv
import time

from .afl_baseline import run_afl
from .common import TARGETS, RunContext, build_targets
from .neat_fuzzer import DEFAULT_CONFIG, run_neat
from .plots import plot_run, read_csv
from .random_fuzzer import run_random


def summarize(run_dir, key: str, seconds: float) -> dict:
    """Итоговые числа по *_timeline.csv / *_crashes.csv одного фаззера."""
    tl = [r for r in read_csv(run_dir / key / f"{key}_timeline.csv")]
    crashes = read_csv(run_dir / key / f"{key}_crashes.csv")
    last = tl[-1] if tl else {}
    final_edges = int(float(last.get("edges", 0) or 0))

    def edges_at(t):
        return max([int(float(r["edges"])) for r in tl if float(r["time_s"]) <= t] or [0])

    def time_to(frac):  # время достижения доли финального покрытия
        for r in tl:
            if final_edges and int(float(r["edges"])) >= frac * final_edges:
                return float(r["time_s"])
        return ""

    execs = [r["total_execs"] for r in tl if r.get("total_execs")]
    return {"fuzzer": key, "seconds": seconds, "final_edges": final_edges,
            "edges_at_25pct_time": edges_at(seconds * 0.25), "edges_at_50pct_time": edges_at(seconds * 0.5),
            "time_to_90pct_edges_s": time_to(0.9),
            "unique_crashes": len(crashes),
            "time_to_first_crash_s": float(crashes[0]["time_s"]) if crashes else "",
            "total_execs": int(float(execs[-1])) if execs else ""}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--target", default="mini_maze", choices=sorted(TARGETS))
    ap.add_argument("--seconds", type=int, default=300, help="время на КАЖДЫЙ фаззер")
    ap.add_argument("--fuzzers", default="afl,neat,random", help="через запятую: afl,neat,random")
    ap.add_argument("--neat-config", default=str(DEFAULT_CONFIG))
    ap.add_argument("--steps", type=int, default=20)
    ap.add_argument("--seed", type=int, default=1)
    a = ap.parse_args()
    fuzzers = [f.strip() for f in a.fuzzers.split(",") if f.strip()]
    ctx = RunContext.create("compare")
    ctx.save_config({"kind": "compare", **vars(a)})
    ctx.say(f"старт сравнения {fuzzers} на {a.target}: по {a.seconds}с каждый "
            f"(≈{a.seconds * len(fuzzers) / 60:.0f} мин), логи: {ctx.logs}")
    try:
        build_targets(ctx, "mini" if a.target.startswith("mini") else a.target)
        for f in fuzzers:
            t0 = time.time()
            ctx.log.info("=== %s ===", f)
            if f == "afl":
                run_afl(ctx, a.target, a.seconds)
            elif f == "neat":
                run_neat(ctx, a.target, a.seconds, config_path=a.neat_config, steps=a.steps, seed=a.seed)
            elif f == "random":
                run_random(ctx, a.target, a.seconds, seed=a.seed)
            else:
                raise ValueError(f"неизвестный фаззер {f}")
            ctx.event("fuzzer_done", fuzzer=f, wall_s=round(time.time() - t0, 1))
        rows = [summarize(ctx.results, f, a.seconds) for f in fuzzers]
        with open(ctx.results / "comparison_summary.csv", "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)
        for r in rows:
            ctx.event("summary", target=a.target, **r)
        plot_run(ctx.results)
        ctx.say("финиш: " + "; ".join(f"{r['fuzzer']}: рёбер={r['final_edges']}, крашей={r['unique_crashes']}"
                                      for r in rows) + f". Результаты: {ctx.results}")
    except Exception as e:
        ctx.log.exception("compare failed: %s", e)
        raise SystemExit(1)
    finally:
        ctx.close()


if __name__ == "__main__":
    main()
