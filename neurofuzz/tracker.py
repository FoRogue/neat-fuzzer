"""Учёт найденного: глобальное покрытие (множество рёбер), корпус интересных входов,
уникальные краши, и запись кривых по времени в CSV того же формата, что у AFL++
(<prefix>_timeline.csv, <prefix>_crashes.csv). Новые рёбра и краши пишутся в events.jsonl.
"""
from __future__ import annotations

import csv
import hashlib
import time
from dataclasses import dataclass, field
from pathlib import Path

from .common import PROJECT_ROOT, TARGETS, RunContext


def load_seeds(target: str) -> list[bytes]:
    d = PROJECT_ROOT / TARGETS[target]["seeds"]
    return [p.read_bytes() for p in sorted(d.iterdir()) if p.is_file()]


@dataclass
class CorpusEntry:
    data: bytes
    edges: dict[int, int]
    found_at: float
    picks: int = 0                     # сколько раз выбирался родителем
    children_new: int = 0              # сколько потомков дали новое покрытие


@dataclass
class Observation:
    new_edges: int = 0                 # новых рёбер в глобальном покрытии
    new_pairs: int = 0                 # новых пар (ребро, класс счётчика) — как «new bits» в AFL
    new_crash: bool = False            # новый уникальный краш
    crashed: bool = False
    timed_out: bool = False


@dataclass
class CoverageTracker:
    ctx: RunContext
    prefix: str                                            # имя подпапки results/<run>/<prefix>/
    started: float = field(default_factory=time.time)
    edges: set[int] = field(default_factory=set)
    pairs: set[tuple[int, int]] = field(default_factory=set)
    crash_edges: set[int] = field(default_factory=set)
    crashes: list[dict] = field(default_factory=list)
    corpus: list[CorpusEntry] = field(default_factory=list)
    execs: int = 0
    timeouts: int = 0
    crash_execs: int = 0                                  # всего падающих исполнений (с повторами)

    def __post_init__(self):
        self.out = self.ctx.results / self.prefix
        (self.out / "crashes").mkdir(parents=True, exist_ok=True)
        self._tl = open(self.out / f"{self.prefix}_timeline.csv", "w", newline="", encoding="utf-8")
        self._tlw = csv.writer(self._tl)
        self._tlw.writerow(["time_s", "edges", "unique_crashes", "total_execs", "corpus_size"])
        self._last_row = -1.0

    def elapsed(self) -> float:
        return time.time() - self.started

    def observe(self, data: bytes, res) -> Observation:
        """Учесть результат одного исполнения; интересные входы добавляются в корпус."""
        self.execs += 1
        ob = Observation(crashed=res.crashed, timed_out=res.timed_out)
        t = self.elapsed()
        if res.timed_out:
            self.timeouts += 1
        new_e = [e for e in res.edges if e not in self.edges]
        new_p = [(e, c) for e, c in res.edges.items() if (e, c) not in self.pairs]
        ob.new_edges, ob.new_pairs = len(new_e), len(new_p)
        if res.crashed:
            self.crash_execs += 1
            # Уникальность краша как в AFL: путь краша содержит ребро, не встречавшееся в прошлых крашах
            if not self.crashes or any(e not in self.crash_edges for e in res.edges):
                ob.new_crash = True
                self._save_crash(data, res, t)
            self.crash_edges.update(res.edges)
        else:
            self.edges.update(new_e)
            self.pairs.update(new_p)
            if new_p and not res.timed_out:
                self.corpus.append(CorpusEntry(data, dict(res.edges), t))
            if new_e:
                self.ctx.event("new_coverage", fuzzer=self.prefix, new_edges=len(new_e),
                               total_edges=len(self.edges), execs=self.execs, input_len=len(data))
        if new_e or ob.new_crash or t - self._last_row >= 1.0:
            self._row(t)
        return ob

    def _save_crash(self, data: bytes, res, t: float) -> None:
        idx = len(self.crashes) + 1
        h = hashlib.sha1(data).hexdigest()[:10]
        name = f"crash_{idx:04d}_t{t:.1f}_{h}"
        (self.out / "crashes" / name).write_bytes(data)
        info = {"time_s": round(t, 3), "crash_index": idx, "file": name, "execs": self.execs,
                "edges": len(res.edges)}
        self.crashes.append(info)
        self.ctx.event("new_crash", fuzzer=self.prefix, **info, input_hex=data[:64].hex())

    def _row(self, t: float) -> None:
        self._tlw.writerow([round(t, 3), len(self.edges), len(self.crashes), self.execs, len(self.corpus)])
        self._tl.flush()
        self._last_row = t

    def finish(self) -> dict:
        self._row(self.elapsed())
        self._tl.close()
        with open(self.out / f"{self.prefix}_crashes.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["time_s", "crash_index", "file"])
            for c in self.crashes:
                w.writerow([c["time_s"], c["crash_index"], c["file"]])
        return {"edges": len(self.edges), "unique_crashes": len(self.crashes), "execs": self.execs,
                "corpus": len(self.corpus), "timeouts": self.timeouts, "crash_execs": self.crash_execs,
                "seconds": round(self.elapsed(), 1)}
