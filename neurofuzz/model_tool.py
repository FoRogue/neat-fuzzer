"""Работа с сохранённой моделью нейрофаззера:
  run    — загрузить лучший геном и фаззить таргет этой фиксированной сетью (без эволюции);
  draw   — нарисовать схему сохранённого генома в SVG;
  resume — продолжить обучение с чекпоинта популяции (вместе с сохранённым корпусом);
  gif    — пересобрать GIF эволюции сети из уже сохранённых кадров/геномов запуска.

Примеры:
  py -m neurofuzz.model_tool run    --model results/<run>/neat/model --seconds 60
  py -m neurofuzz.model_tool draw   --model results/<run>/neat/model --out best.svg
  py -m neurofuzz.model_tool resume --checkpoint results/<run>/neat/checkpoints/neat-checkpoint-50 --seconds 120
  py -m neurofuzz.model_tool gif    --run results/<run>
"""
from __future__ import annotations

import argparse
import json
import pickle
import random
import time
from pathlib import Path

import neat

from .common import RunContext
from .neat_fuzzer import DEFAULT_CONFIG, load_config, run_neat
from .plots import plot_run
from .policy import bucket_totals, coverage_features, network_mutate
from .tracker import CoverageTracker, load_seeds


def load_model(model_dir: Path):
    """-> (геном, конфиг NEAT, model_info). Конфиг берётся сохранённый рядом с моделью."""
    with open(model_dir / "best_genome.pkl", "rb") as f:
        genome = pickle.load(f)
    config = load_config(model_dir / "neat_config.ini")
    info = json.loads((model_dir / "model_info.json").read_text(encoding="utf-8"))
    return genome, config, info


def cmd_run(a) -> None:
    from .executor import Executor

    genome, config, info = load_model(a.model)
    target = a.target or info["target"]
    ctx = RunContext.create("model-run")
    ctx.save_config({"kind": "model_run", "model": str(a.model), "model_info": info, "target": target,
                     "seconds": a.seconds})
    ctx.say(f"старт: модель {a.model} (fitness {info['best_fitness']}) на {target}, {a.seconds:g}с")
    net = neat.nn.FeedForwardNetwork.create(genome, config)
    rng = random.Random(a.seed)
    try:
        with Executor(target, log=ctx.log) as ex:
            tr = CoverageTracker(ctx, "neat")
            seeds = load_seeds(target)
            for d, r in zip(seeds, ex.run_batch(seeds)):
                tr.observe(d, r)
            deadline = time.time() + a.seconds
            while time.time() < deadline:
                batch, parents = [], []
                for _ in range(a.batch):
                    p = rng.choices(tr.corpus, weights=[1 / (1 + e.picks) ** 0.5 for e in tr.corpus])[0]
                    p.picks += 1
                    cov = coverage_features(p.edges, bucket_totals(tr.edges), len(tr.edges))
                    batch.append(network_mutate(net, p, tr.corpus, cov, rng))
                    parents.append(p)
                for d, r, p in zip(batch, ex.run_batch(batch), parents):
                    if tr.observe(d, r).new_pairs:
                        p.children_new += 1
            s = tr.finish()
        plot_run(ctx.results)
        ctx.say(f"финиш: рёбер={s['edges']}, крашей={s['unique_crashes']}, исполнений={s['execs']}; {ctx.results}")
    finally:
        ctx.close()


def cmd_draw(a) -> None:
    from .viz import draw_genome

    genome, config, info = load_model(a.model)
    out = a.out or (a.model / "best_genome.svg")
    draw_genome(genome, config, out, title=f"Лучший геном: {info['target']}, fitness {info['best_fitness']:.1f}")
    print(f"[neurofuzz] схема: {out}")


def cmd_resume(a) -> None:
    ckpt = a.checkpoint
    run_dir = ckpt.parent.parent.parent              # results/<run>/neat/checkpoints/<file>
    info_path = run_dir / "neat" / "model" / "model_info.json"
    target = a.target or (json.loads(info_path.read_text(encoding="utf-8"))["target"]
                          if info_path.exists() else "mini_maze")
    cfg = run_dir / "neat" / "model" / "neat_config.ini"
    ctx = RunContext.create("neat-resume")
    ctx.save_config({"kind": "neat_resume", "checkpoint": str(ckpt), "target": target, "seconds": a.seconds})
    ctx.say(f"старт: продолжение обучения с {ckpt.name} ({target}, {a.seconds:g}с)")
    try:
        s = run_neat(ctx, target, a.seconds, checkpoint=ckpt,
                     config_path=cfg if cfg.exists() else DEFAULT_CONFIG)
        plot_run(ctx.results)
        ctx.say(f"финиш: поколений={s['generations']}, рёбер={s['edges']}, крашей={s['unique_crashes']}; "
                f"{ctx.results}")
    except Exception as e:
        ctx.log.exception("resume failed: %s", e)
        raise SystemExit(1)
    finally:
        ctx.close()


def cmd_gif(a) -> None:
    from .viz import build_gif, draw_genome

    frames = a.run / "network" / "frames"
    genomes = sorted((a.run / "neat" / "genomes").glob("gen_*.pkl"))
    if a.redraw or not any(frames.glob("gen_*.png")):
        config = load_config(a.run / "neat" / "model" / "neat_config.ini")
        frames.mkdir(parents=True, exist_ok=True)
        every = max(1, -(-len(genomes) // a.max_frames))
        for p in genomes[::every]:
            with open(p, "rb") as f:
                g = pickle.load(f)
            draw_genome(g, config, frames / f"{p.stem}.svg", frames / f"{p.stem}.png",
                        title=f"Лучшая сеть поколения {int(p.stem.split('_')[1])} (fitness {g.fitness:.1f})")
    out = build_gif(frames, a.run / "network" / "evolution.gif", a.ms)
    print(f"[neurofuzz] GIF: {out}" if out else "[neurofuzz] ERROR: нет кадров и геномов")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="фаззить сохранённой сетью")
    r.add_argument("--model", type=Path, required=True, help="папка results/<run>/neat/model")
    r.add_argument("--target", default=None, help="по умолчанию — таргет из model_info.json")
    r.add_argument("--seconds", type=float, default=60)
    r.add_argument("--batch", type=int, default=100)
    r.add_argument("--seed", type=int, default=1)
    d = sub.add_parser("draw", help="схема генома в SVG")
    d.add_argument("--model", type=Path, required=True)
    d.add_argument("--out", type=Path, default=None)
    s = sub.add_parser("resume", help="продолжить обучение с чекпоинта")
    s.add_argument("--checkpoint", type=Path, required=True)
    s.add_argument("--target", default=None)
    s.add_argument("--seconds", type=float, default=120)
    g = sub.add_parser("gif", help="пересобрать GIF из кадров")
    g.add_argument("--run", type=Path, required=True, help="папка results/<run>")
    g.add_argument("--redraw", action="store_true", help="перерисовать кадры из сохранённых геномов")
    g.add_argument("--max-frames", type=int, default=120)
    g.add_argument("--ms", type=int, default=400, help="мс на кадр")
    a = ap.parse_args()
    {"run": cmd_run, "draw": cmd_draw, "resume": cmd_resume, "gif": cmd_gif}[a.cmd](a)


if __name__ == "__main__":
    main()
