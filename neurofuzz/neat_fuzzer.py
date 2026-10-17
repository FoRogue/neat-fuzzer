"""Нейроэволюционный фаззер: популяция сетей NEAT, каждая сеть — политика мутаций.
Цикл: поколение -> оценка (каждая сеть мутирует одни и те же входы корпуса, исполнитель
прогоняет результаты, fitness = прирост покрытия + краши) -> отбор/размножение NEAT.
Сохраняет лучший геном, чекпоинты популяции (+ корпус), кадры сети, GIF, графики, CSV.

Запуск:  py -m neurofuzz.neat_fuzzer --target mini_maze --seconds 300
"""
from __future__ import annotations

import argparse
import contextlib
import csv
import datetime as dt
import gzip
import io
import json
import pickle
import random
import shutil
import statistics
import time
from pathlib import Path

import neat

from .common import PROJECT_ROOT, TARGETS, RunContext, build_targets, version_string
from .executor import Executor
from .mutations import N_OPS, OP_NAMES
from .policy import N_INPUTS, N_OUTPUTS, bucket_totals, coverage_features, network_mutate
from .tracker import CorpusEntry, CoverageTracker, load_seeds

DEFAULT_CONFIG = PROJECT_ROOT / "configs" / "neat_config.ini"
# Веса fitness: новое ребро ценнее всего, новый краш — ещё ценнее; новые счётчики попаданий
# и разнообразие путей дают «градиент», когда новых рёбер долго нет.
# distinct_input поощряет разнообразие порождаемых входов: когда покрытие не растёт (магические
# байты), только оно отличает «исследующую» сеть от сети, всё время делающей одну и ту же мутацию.
FITNESS_WEIGHTS = {"new_edge": 10.0, "new_pair": 1.0, "new_crash": 100.0, "distinct_path": 0.2,
                   "distinct_input": 0.05}


def load_config(path: Path) -> neat.Config:
    cfg = neat.Config(neat.DefaultGenome, neat.DefaultReproduction, neat.DefaultSpeciesSet,
                      neat.DefaultStagnation, str(path))
    gc = cfg.genome_config
    if gc.num_inputs != N_INPUTS or gc.num_outputs != N_OUTPUTS:
        raise ValueError(f"конфиг NEAT: нужно num_inputs={N_INPUTS}, num_outputs={N_OUTPUTS}")
    return cfg


class CorpusCheckpointer(neat.Checkpointer):
    """Стандартный neat.Checkpointer + рядом сохраняет корпус фаззера (иначе после
    продолжения обучения сети начинали бы с нуля покрытия)."""

    def __init__(self, every: int, prefix: str, fuzzer: "NeatFuzzer"):
        super().__init__(every, None, prefix)
        self.fuzzer = fuzzer

    def __reduce__(self):
        # Репортёр попадает в pickle чекпоинта (через species_set.reporters). Сохраняем вместо него
        # пустой BaseReporter: иначе pickle тянет фаззер с открытыми файлами, а класс из __main__
        # не находится при загрузке. При восстановлении neat-python всё равно ставит новые репортёры.
        return (neat.reporting.BaseReporter, ())

    def save_checkpoint(self, config, population, species_set, generation):
        with contextlib.redirect_stdout(io.StringIO()):   # neat печатает "Saving checkpoint" в консоль
            super().save_checkpoint(config, population, species_set, generation)
        path = Path(f"{self.filename_prefix}{generation}.corpus.gz")
        with gzip.open(path, "wb") as f:
            pickle.dump([e.data for e in self.fuzzer.tracker.corpus], f)
        self.fuzzer.ctx.event("checkpoint", generation=generation, path=f"{self.filename_prefix}{generation}")


class NeatFuzzer:
    def __init__(self, ctx: RunContext, executor: Executor, target: str, seconds: float,
                 config_path: Path = DEFAULT_CONFIG, steps: int = 20, checkpoint_every: int = 10,
                 seed: int = 1, checkpoint: Path | None = None, prefix: str = "neat"):
        self.ctx, self.ex, self.target, self.seconds = ctx, executor, target, seconds
        self.steps, self.seed = steps, seed
        self.rng = random.Random(seed)
        self.config_path = Path(config_path)
        self.config = load_config(self.config_path)
        self.tracker = CoverageTracker(ctx, prefix)
        self.out = ctx.results / prefix
        for sub in ("genomes", "checkpoints", "model"):
            (self.out / sub).mkdir(parents=True, exist_ok=True)
        self.gen_csv_path = self.out / "generations.csv"
        self._gen_csv = None
        self.best_ever = None
        self.deadline = 0.0
        self.gen_records: list[dict] = []
        if checkpoint:
            self.pop = neat.Checkpointer.restore_checkpoint(str(checkpoint), new_config=None)
            self.config = self.pop.config
            self.resumed_from = str(checkpoint)
        else:
            self.pop = neat.Population(self.config, seed=seed)
            self.resumed_from = None
        self.pop.add_reporter(CorpusCheckpointer(checkpoint_every,
                                                 str(self.out / "checkpoints" / "neat-checkpoint-"), self))
        self.start_generation = self.pop.generation

    # --- корпус -----------------------------------------------------------------------------
    def load_initial_corpus(self, checkpoint: Path | None) -> None:
        datas = load_seeds(self.target)
        corpus_file = Path(f"{checkpoint}.corpus.gz") if checkpoint else None
        if corpus_file and corpus_file.exists():
            with gzip.open(corpus_file, "rb") as f:
                datas = pickle.load(f) + datas
            self.ctx.event("corpus_restored", file=str(corpus_file), entries=len(datas))
        for d, r in zip(datas, self.ex.run_batch(datas)):
            self.tracker.observe(d, r)
        if not self.tracker.corpus:  # все сиды упали — добавим хоть что-то
            self.tracker.corpus.append(CorpusEntry(datas[0] if datas else b"\x00", {}, 0.0))

    def select_parent(self) -> CorpusEntry:
        """AFL-подобно: реже выбиравшиеся и «плодовитые» входы — чаще."""
        c = self.tracker.corpus
        w = [(1.0 + e.children_new) / (1.0 + e.picks) ** 0.5 for e in c]
        p = self.rng.choices(c, weights=w)[0]
        p.picks += 1
        return p

    # --- оценка поколения -------------------------------------------------------------------
    def eval_genomes(self, genomes, config) -> None:
        t_gen = time.time()
        tr = self.tracker
        nets = [neat.nn.FeedForwardNetwork.create(g, config) for _, g in genomes]
        base_edges, base_pairs = set(tr.edges), set(tr.pairs)
        n_crash0, crash_execs0 = len(tr.crashes), tr.crash_execs
        stats = [{"edges": set(), "pairs": set(), "crashes": 0, "paths": set(), "inputs": set(), "execs": 0}
                 for _ in genomes]
        op_counter = [0] * N_OPS
        steps_done = 0
        for _ in range(self.steps):
            if time.time() >= self.deadline:
                break
            parent = self.select_parent()       # один родитель на шаг для всех сетей — честное сравнение
            totals = bucket_totals(tr.edges)
            cov = coverage_features(parent.edges, totals, len(tr.edges))
            children = [network_mutate(net, parent, tr.corpus, cov, self.rng, op_counter) for net in nets]
            results = self.ex.run_batch(children)
            for st, child, res in zip(stats, children, results):
                ob = tr.observe(child, res)
                st["execs"] += 1
                st["edges"].update(e for e in res.edges if e not in base_edges and not res.crashed)
                st["pairs"].update(p for p in res.edges.items() if p not in base_pairs and not res.crashed)
                st["crashes"] += int(ob.new_crash)
                st["paths"].add(hash(frozenset(res.edges)))
                st["inputs"].add(hash(child))
                if ob.new_pairs and not res.crashed:
                    parent.children_new += 1
            steps_done += 1
        w = FITNESS_WEIGHTS
        for (gid, g), st in zip(genomes, stats):
            g.fitness = (w["new_edge"] * len(st["edges"]) + w["new_pair"] * len(st["pairs"]) +
                         w["new_crash"] * st["crashes"] + w["distinct_path"] * len(st["paths"]) +
                         w["distinct_input"] * len(st["inputs"]))
        self._record_generation(genomes, stats, steps_done, op_counter, time.time() - t_gen,
                                len(tr.edges) - len(base_edges), len(tr.crashes) - n_crash0,
                                tr.crash_execs - crash_execs0)

    def _record_generation(self, genomes, stats, steps_done, op_counter, gen_s, new_edges, new_crashes,
                           crash_execs):
        from .viz import complexity

        fits = [g.fitness for _, g in genomes]
        best_i = max(range(len(genomes)), key=lambda i: fits[i])
        best = genomes[best_i][1]
        if self.best_ever is None or best.fitness > self.best_ever.fitness:
            self.best_ever = pickle.loads(pickle.dumps(best))
            self.best_ever_generation = self.pop.generation
        cx = complexity(best)
        rec = {"generation": self.pop.generation, "time_s": round(self.tracker.elapsed(), 2),
               "best_fitness": round(best.fitness, 3), "mean_fitness": round(statistics.mean(fits), 3),
               "stdev_fitness": round(statistics.pstdev(fits), 3), "edges": len(self.tracker.edges),
               "unique_crashes": len(self.tracker.crashes), "execs": self.tracker.execs,
               "corpus": len(self.tracker.corpus), "species": len(self.pop.species.species),
               "pop_size": len(genomes), "steps": steps_done, "gen_seconds": round(gen_s, 3),
               "new_edges_gen": new_edges, "new_crashes_gen": new_crashes, "crash_execs_gen": crash_execs,
               "best_genome_id": best.key, "best_new_edges": len(stats[best_i]["edges"]),
               "best_crashes": stats[best_i]["crashes"], "best_hidden": cx["hidden"],
               "best_nodes": cx["nodes"], "best_connections": cx["connections"],
               "best_enabled_connections": cx["enabled_connections"],
               "ops": dict(zip(OP_NAMES, op_counter))}
        self.ctx.generations.write(rec)
        self.ctx.log.info("gen %d: best=%.1f mean=%.1f edges=%d crashes=%d species=%d hidden=%d conns=%d (%.2fs)",
                          rec["generation"], rec["best_fitness"], rec["mean_fitness"], rec["edges"],
                          rec["unique_crashes"], rec["species"], rec["best_hidden"],
                          rec["best_enabled_connections"], gen_s)
        flat = {k: v for k, v in rec.items() if k != "ops"}
        if self._gen_csv is None:
            self._gen_file = open(self.gen_csv_path, "w", newline="", encoding="utf-8")
            self._gen_csv = csv.DictWriter(self._gen_file, fieldnames=list(flat))
            self._gen_csv.writeheader()
        self._gen_csv.writerow(flat)
        self._gen_file.flush()
        self.gen_records.append(rec)
        # лучший геном каждого поколения — для кадров схемы и GIF (рисуются после фаззинга)
        with open(self.out / "genomes" / f"gen_{self.pop.generation:04d}.pkl", "wb") as f:
            pickle.dump(best, f)

    # --- основной цикл ----------------------------------------------------------------------
    def run(self, checkpoint: Path | None = None) -> dict:
        self.tracker.started = time.time()
        self.deadline = self.tracker.started + self.seconds
        self.load_initial_corpus(checkpoint)
        while time.time() < self.deadline:
            try:
                self.pop.run(self.eval_genomes, 1)
            except neat.CompleteExtinctionException:
                self.ctx.log.warning("полное вымирание популяции — создаём новую")
                self.pop = neat.Population(self.config, seed=self.rng.randrange(1 << 30))
        summary = self.tracker.finish()
        if self._gen_csv is not None:
            self._gen_file.close()
        summary["generations"] = len(self.gen_records)
        return summary

    def save_model(self) -> Path:
        """best_genome.pkl + конфиг NEAT + model_info.json — всё для воспроизведения."""
        mdir = self.out / "model"
        with open(mdir / "best_genome.pkl", "wb") as f:
            pickle.dump(self.best_ever, f)
        shutil.copy(self.config_path, mdir / "neat_config.ini")
        last = self.gen_records[-1] if self.gen_records else {}
        info = {"target": self.target, "binary": TARGETS[self.target]["binary"],
                "code_version": version_string(), "neat_python": getattr(neat, "__version__", "2.0.0"),
                "date": dt.datetime.now().isoformat(timespec="seconds"), "run": self.ctx.name,
                "best_fitness": self.best_ever.fitness if self.best_ever else None,
                "best_generation": getattr(self, "best_ever_generation", None),
                "best_genome_key": self.best_ever.key if self.best_ever else None,
                "generations": len(self.gen_records), "last_generation": last.get("generation"),
                "seconds": self.seconds, "steps_per_generation": self.steps, "seed": self.seed,
                "fitness_weights": FITNESS_WEIGHTS, "n_inputs": N_INPUTS, "n_outputs": N_OUTPUTS,
                "resumed_from": self.resumed_from, "final_edges": len(self.tracker.edges),
                "final_unique_crashes": len(self.tracker.crashes),
                "checkpoints": sorted(p.name for p in (self.out / "checkpoints").glob("neat-checkpoint-*")
                                      if not p.name.endswith(".gz"))}
        (mdir / "model_info.json").write_text(json.dumps(info, indent=2, ensure_ascii=False), encoding="utf-8")
        self.ctx.event("model_saved", path=str(mdir), best_fitness=info["best_fitness"])
        return mdir

    def render_network(self, max_frames: int = 120) -> Path | None:
        """Кадры SVG (+PNG для GIF) лучшей сети каждого N-го поколения и GIF из них."""
        from .viz import build_gif, draw_genome

        files = sorted((self.out / "genomes").glob("gen_*.pkl"))
        if not files:
            return None
        every = max(1, -(-len(files) // max_frames))
        pick = files[::every]
        if pick[-1] != files[-1]:
            pick.append(files[-1])
        frames = self.ctx.results / "network" / "frames"
        frames.mkdir(parents=True, exist_ok=True)
        for p in pick:
            with open(p, "rb") as f:
                g = pickle.load(f)
            gen = int(p.stem.split("_")[1])
            draw_genome(g, self.config, frames / f"{p.stem}.svg", frames / f"{p.stem}.png",
                        title=f"Лучшая сеть поколения {gen} (fitness {g.fitness:.1f})")
        if self.best_ever is not None:
            draw_genome(self.best_ever, self.config, self.out / "model" / "best_genome.svg",
                        title=f"Лучший геном (fitness {self.best_ever.fitness:.1f})")
        gif = build_gif(frames, self.ctx.results / "network" / "evolution.gif")
        self.ctx.event("network_rendered", frames=len(pick), every=every, gif=str(gif))
        return gif


def run_neat(ctx: RunContext, target: str, seconds: float, *, config_path: Path = DEFAULT_CONFIG,
             steps: int = 20, checkpoint_every: int = 10, seed: int = 1,
             checkpoint: Path | None = None, render: bool = True) -> dict:
    """Полный запуск нейрофаззера (используется и в compare.py, и в model_tool.py)."""
    with Executor(target, log=ctx.log) as ex:
        nf = NeatFuzzer(ctx, ex, target, seconds, config_path, steps, checkpoint_every, seed, checkpoint)
        ctx.event("neat_start", target=target, seconds=seconds, steps=steps,
                  pop_size=nf.config.pop_size, start_generation=nf.start_generation)
        summary = nf.run(checkpoint)
    summary["model_dir"] = str(nf.save_model())
    if render:
        summary["gif"] = str(nf.render_network())
    summary["best_fitness"] = nf.best_ever.fitness if nf.best_ever else None
    ctx.event("neat_finish", **summary)
    return summary


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--target", default="mini_maze", choices=sorted(TARGETS))
    ap.add_argument("--seconds", type=float, default=300)
    ap.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    ap.add_argument("--steps", type=int, default=20, help="мутаций на одну сеть за поколение")
    ap.add_argument("--checkpoint-every", type=int, default=10)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--no-build", action="store_true")
    a = ap.parse_args()
    from .plots import plot_run

    ctx = RunContext.create("neat")
    ctx.save_config({"kind": "neat_fuzzer", **{k: str(v) for k, v in vars(a).items()},
                     "fitness_weights": FITNESS_WEIGHTS,
                     "neat_config_text": a.config.read_text(encoding="utf-8")})
    ctx.say(f"старт нейрофаззера: таргет={a.target}, время={a.seconds:g}с, логи: {ctx.logs}")
    try:
        if not a.no_build:
            build_targets(ctx, "mini" if a.target.startswith("mini") else a.target)
        s = run_neat(ctx, a.target, a.seconds, config_path=a.config, steps=a.steps,
                     checkpoint_every=a.checkpoint_every, seed=a.seed)
        plot_run(ctx.results)
        ctx.say(f"финиш: поколений={s['generations']}, рёбер={s['edges']}, крашей={s['unique_crashes']}, "
                f"исполнений={s['execs']}; результаты: {ctx.results}")
    except Exception as e:
        ctx.log.exception("neat_fuzzer failed: %s", e)
        raise SystemExit(1)
    finally:
        ctx.close()


if __name__ == "__main__":
    main()
