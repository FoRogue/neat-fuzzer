"""Исполнитель: запускает таргет в Docker на заданных байтах и возвращает карту покрытия
(edge id -> класс счётчика AFL) и флаг краша. Внутри контейнера постоянно работает
docker/executor_server.py, общение — бинарный протокол через stdin/stdout `docker run -i`.

Самопроверка (случайные мутации):  py -m neurofuzz.executor --target mini_maze --n 3000
"""
from __future__ import annotations

import argparse
import random
import struct
import subprocess
import time
import uuid
from dataclasses import dataclass

from .common import AFL_IMAGE, NO_ASLR, TARGETS, RunContext, build_targets, docker_volume_arg

STATUS_OK, STATUS_TIMEOUT, STATUS_CRASH = 0, 1, 2


@dataclass
class ExecResult:
    status: int                 # 0 ok, 1 таймаут, 2 краш
    edges: dict[int, int]       # edge id -> класс счётчика попаданий (1,2,4,8,...,128 по AFL)

    @property
    def crashed(self) -> bool:
        return self.status == STATUS_CRASH

    @property
    def timed_out(self) -> bool:
        return self.status == STATUS_TIMEOUT


class Executor:
    """Долгоживущий контейнер-исполнитель. Использовать как контекстный менеджер."""

    def __init__(self, target: str, timeout_ms: int = 1000, log=None):
        self.target = target
        self.timeout_ms = timeout_ms
        self.log = log
        self.name = f"neurofuzz_exec_{uuid.uuid4().hex[:8]}"
        self.proc: subprocess.Popen | None = None
        self.total_execs = 0
        self.exec_time = 0.0

    def start(self) -> "Executor":
        t = TARGETS[self.target]
        cmd = ["docker", "run", "--rm", "-i", "--name", self.name,
               "--security-opt", "seccomp=unconfined", "--tmpfs", "/fz:exec,size=512m",
               "-v", docker_volume_arg(), AFL_IMAGE, *NO_ASLR.split(),
               "python3", "-u", "/work/docker/executor_server.py", str(self.timeout_ms),
               t["binary"], *t["args"]]
        if self.log:
            self.log.info("executor start: %s", " ".join(cmd))
        self.proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, bufsize=0)
        line = self.proc.stdout.readline()
        if line.strip() != b"READY":
            err = self.proc.stderr.read().decode(errors="replace") if self.proc.poll() is not None else ""
            raise RuntimeError(f"executor не запустился: {line!r} {err[:500]}")
        return self

    def _read(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = self.proc.stdout.read(n - len(buf))
            if not chunk:
                err = self.proc.stderr.read().decode(errors="replace")
                raise RuntimeError(f"executor оборвал соединение: {err[:500]}")
            buf += chunk
        return bytes(buf)

    def run_batch(self, datas: list[bytes]) -> list[ExecResult]:
        """Прогнать пачку входов. Чем больше пачка, тем меньше накладные расходы на вызов."""
        if not datas:
            return []
        t0 = time.perf_counter()
        req = [b"B", struct.pack("<I", len(datas))]
        for d in datas:
            req += [struct.pack("<I", len(d)), d]
        self.proc.stdin.write(b"".join(req))
        self.proc.stdin.flush()
        (n,) = struct.unpack("<I", self._read(4))
        results = []
        for _ in range(n):
            status, k = struct.unpack("<BI", self._read(5))
            raw = self._read(5 * k)
            edges = {}
            for i in range(k):
                e, c = struct.unpack_from("<IB", raw, 5 * i)
                edges[e] = c
            results.append(ExecResult(status, edges))
        self.total_execs += n
        self.exec_time += time.perf_counter() - t0
        return results

    def run(self, data: bytes) -> ExecResult:
        return self.run_batch([data])[0]

    def close(self) -> None:
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.stdin.write(b"Q")
                self.proc.stdin.flush()
                self.proc.wait(timeout=10)
            except Exception:
                subprocess.run(["docker", "rm", "-f", self.name], capture_output=True)
        self.proc = None

    def __enter__(self) -> "Executor":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.close()


def main() -> None:
    """Самопроверка: известные входы (краш/не краш) + N случайных мутаций сидов."""
    from .mutations import havoc
    from .tracker import CoverageTracker, load_seeds

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--target", default="mini_maze", choices=sorted(TARGETS))
    ap.add_argument("--n", type=int, default=3000, help="число случайных мутаций")
    ap.add_argument("--batch", type=int, default=100)
    a = ap.parse_args()
    ctx = RunContext.create("exectest")
    ctx.save_config({"kind": "executor_selftest", **vars(a)})
    ctx.say(f"старт самопроверки исполнителя: {a.target}, n={a.n}")
    try:
        build_targets(ctx, "mini" if a.target.startswith("mini") else a.target)
        with Executor(a.target, log=ctx.log) as ex:
            if a.target == "mini_maze":
                known = {b"NEATD0/": STATUS_CRASH, b"NEATWFUZZING": STATUS_CRASH,
                         b"NEATD5/": STATUS_OK, b"hello": STATUS_OK}
                res = ex.run_batch(list(known))
                for (data, want), r in zip(known.items(), res):
                    ok = r.status == want
                    ctx.event("known_input", data=data.decode(), want=want, got=r.status,
                              edges=len(r.edges), ok=ok)
                    if not ok:
                        ctx.log.error("неверный статус для %r: ждали %d, получили %d", data, want, r.status)
            tracker = CoverageTracker(ctx, "exectest")
            rng = random.Random(1)
            seeds = load_seeds(a.target)
            for s, r in zip(seeds, ex.run_batch(seeds)):
                tracker.observe(s, r)
            t0 = time.time()
            done = 0
            while done < a.n:
                batch = [havoc(rng.choice(tracker.corpus).data, rng, tracker.corpus) for _ in range(a.batch)]
                for d, r in zip(batch, ex.run_batch(batch)):
                    tracker.observe(d, r)
                done += len(batch)
            dt = time.time() - t0
            tracker.finish()
            ctx.event("selftest_summary", execs=done, seconds=round(dt, 2),
                      execs_per_sec=round(done / dt, 1), edges=len(tracker.edges),
                      unique_crashes=len(tracker.crashes), corpus=len(tracker.corpus))
            ctx.say(f"финиш: {done} исполнений за {dt:.1f}с ({done / dt:.0f}/с), рёбер={len(tracker.edges)}, "
                    f"уникальных крашей={len(tracker.crashes)}, корпус={len(tracker.corpus)}")
    except Exception as e:
        ctx.log.exception("selftest failed: %s", e)
        raise SystemExit(1)
    finally:
        ctx.close()


if __name__ == "__main__":
    main()
