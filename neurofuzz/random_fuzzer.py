"""Случайный фаззер — контрольная группа: тот же исполнитель, тот же корпус и выбор родителя,
те же 8 операторов мутаций, но оператор/позицию/значение выбирает генератор случайных чисел
(havoc), а не нейросеть. Разница «NEAT − random» показывает вклад именно нейросети.

Запуск:  py -m neurofuzz.random_fuzzer --target mini_maze --seconds 120
"""
from __future__ import annotations

import argparse
import random
import time

from .common import TARGETS, RunContext, build_targets
from .executor import Executor
from .mutations import havoc
from .tracker import CorpusEntry, CoverageTracker, load_seeds


def run_random(ctx: RunContext, target: str, seconds: float, batch: int = 200, seed: int = 1) -> dict:
    rng = random.Random(seed)
    ctx.event("random_start", target=target, seconds=seconds, batch=batch)
    with Executor(target, log=ctx.log) as ex:
        tr = CoverageTracker(ctx, "random")
        seeds = load_seeds(target)
        for d, r in zip(seeds, ex.run_batch(seeds)):
            tr.observe(d, r)
        if not tr.corpus:
            tr.corpus.append(CorpusEntry(seeds[0], {}, 0.0))
        deadline = tr.started + seconds
        while time.time() < deadline:
            parents = rng.choices(tr.corpus, weights=[(1.0 + e.children_new) / (1.0 + e.picks) ** 0.5
                                                      for e in tr.corpus], k=batch)
            children = []
            for p in parents:
                p.picks += 1
                children.append(havoc(p.data, rng, tr.corpus))
            for d, r, p in zip(children, ex.run_batch(children), parents):
                if tr.observe(d, r).new_pairs and not r.crashed:
                    p.children_new += 1
        s = tr.finish()
    ctx.event("random_finish", **s)
    return s


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--target", default="mini_maze", choices=sorted(TARGETS))
    ap.add_argument("--seconds", type=float, default=120)
    ap.add_argument("--seed", type=int, default=1)
    a = ap.parse_args()
    ctx = RunContext.create("random")
    ctx.save_config({"kind": "random_fuzzer", **vars(a)})
    ctx.say(f"старт случайного фаззера: {a.target}, {a.seconds:g}с")
    try:
        build_targets(ctx, "mini" if a.target.startswith("mini") else a.target)
        s = run_random(ctx, a.target, a.seconds, seed=a.seed)
        ctx.say(f"финиш: рёбер={s['edges']}, крашей={s['unique_crashes']}, исполнений={s['execs']}")
    except Exception as e:
        ctx.log.exception("random fuzzer failed: %s", e)
        raise SystemExit(1)
    finally:
        ctx.close()


if __name__ == "__main__":
    main()
