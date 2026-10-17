"""Общие вещи для всех скриптов: пути проекта, папки запуска с датой/временем,
логирование (JSON Lines + текстовый лог ошибок) и запуск команд в Docker.
Консоль получает только старт, финиш и ошибки — всё остальное идёт в logs/<run>/.
"""
from __future__ import annotations

import datetime as _dt
import json
import logging
import os
import platform
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RESULTS_ROOT = PROJECT_ROOT / "results"
LOGS_ROOT = PROJECT_ROOT / "logs"
AFL_IMAGE = os.environ.get("NEUROFUZZ_AFL_IMAGE", "aflplusplus/aflplusplus:v4.21c")
CONTAINER_WORK = "/work"  # куда монтируется папка проекта внутри контейнера
# ASAN из clang 16 случайно падает при старте на ядре WSL2 6.x (vm.mmap_rnd_bits=32).
# Лечится отключением ASLR: setarch -R (наследуется дочерними процессами). Docker по умолчанию
# запрещает personality(), поэтому контейнеры запускаются с seccomp=unconfined.
NO_ASLR = "setarch x86_64 -R"

# Известные таргеты: путь к бинарнику (внутри контейнера), папка сидов, как подавать вход.
TARGETS = {
    "mini_maze": {"binary": "/work/build/mini/mini_maze", "seeds": "targets/mini/seeds/mini_maze",
                  "args": ["@@"]},
    "mini_tlv": {"binary": "/work/build/mini/mini_tlv", "seeds": "targets/mini/seeds/mini_tlv",
                 "args": ["@@"]},
    "libpng": {"binary": "/work/build/libpng/libpng_read_fuzzer", "seeds": "targets/libpng/seeds",
               "args": ["@@"]},
}


def version_string() -> str:
    """Версия кода = короткий хэш git-коммита (+ '-dirty', если есть незакоммиченные правки)."""
    try:
        h = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=PROJECT_ROOT,
                           capture_output=True, text=True, timeout=10).stdout.strip()
        dirty = subprocess.run(["git", "status", "--porcelain"], cwd=PROJECT_ROOT,
                               capture_output=True, text=True, timeout=10).stdout.strip()
        return (h or "nogit") + ("-dirty" if dirty else "")
    except Exception:
        return "unknown"


def timestamp() -> str:
    return _dt.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


class _JsonlWriter:
    def __init__(self, path: Path):
        self.path = path
        self._f = open(path, "a", encoding="utf-8")

    def write(self, record: dict) -> None:
        record = {"ts": round(time.time(), 3), **record}
        self._f.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
        self._f.flush()

    def close(self) -> None:
        self._f.close()


@dataclass
class RunContext:
    """Один запуск = пара папок results/<имя>/ и logs/<имя>/.

    Файлы логов:
      run.log            — человекочитаемый текстовый лог (всё подряд)
      errors.log         — только ошибки и предупреждения
      events.jsonl       — события (новое покрытие, новый краш, ошибки таргета, ...)
      generations.jsonl  — по одной строке на поколение NEAT
      config.json        — конфигурация запуска
    """
    name: str
    results: Path
    logs: Path
    log: logging.Logger
    events: _JsonlWriter
    generations: _JsonlWriter
    started: float = field(default_factory=time.time)

    @classmethod
    def create(cls, kind: str, run_name: str | None = None) -> "RunContext":
        name = run_name or f"{timestamp()}_{kind}"
        results = RESULTS_ROOT / name
        logs = LOGS_ROOT / name
        results.mkdir(parents=True, exist_ok=True)
        logs.mkdir(parents=True, exist_ok=True)

        log = logging.getLogger(f"neurofuzz.{name}")
        log.setLevel(logging.DEBUG)
        log.propagate = False
        fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(message)s")
        fh = logging.FileHandler(logs / "run.log", encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(fmt)
        eh = logging.FileHandler(logs / "errors.log", encoding="utf-8")
        eh.setLevel(logging.WARNING)
        eh.setFormatter(fmt)
        ch = logging.StreamHandler(sys.stderr)  # консоль: только ошибки (старт/финиш — через say())
        ch.setLevel(logging.ERROR)
        ch.setFormatter(logging.Formatter("[neurofuzz] %(levelname)s: %(message)s"))
        for h in (fh, eh, ch):
            log.addHandler(h)
        ctx = cls(name=name, results=results, logs=logs, log=log,
                  events=_JsonlWriter(logs / "events.jsonl"),
                  generations=_JsonlWriter(logs / "generations.jsonl"))
        return ctx

    def say(self, msg: str) -> None:
        """Короткое сообщение в консоль (старт/финиш) + в лог."""
        print(f"[neurofuzz] {msg}", flush=True)
        self.log.info(msg)

    def event(self, kind: str, **data) -> None:
        self.events.write({"event": kind, "t": round(time.time() - self.started, 3), **data})
        self.log.debug("event %s %s", kind, json.dumps(data, ensure_ascii=False, default=str)[:500])

    def save_config(self, config: dict) -> None:
        full = {"run": self.name, "version": version_string(), "python": sys.version.split()[0],
                "platform": platform.platform(), "afl_image": AFL_IMAGE, **config}
        (self.logs / "config.json").write_text(json.dumps(full, indent=2, ensure_ascii=False),
                                               encoding="utf-8")
        self.events.write({"event": "config", **full})

    def close(self) -> None:
        self.events.close()
        self.generations.close()
        for h in list(self.log.handlers):
            h.close()
            self.log.removeHandler(h)


def docker_volume_arg() -> str:
    return f"{PROJECT_ROOT}:{CONTAINER_WORK}"


def docker_run_cmd(inner: str, name: str | None = None, interactive: bool = False) -> list[str]:
    """Команда `docker run` с примонтированным проектом; inner выполняется через bash -c."""
    cmd = ["docker", "run", "--rm", "--security-opt", "seccomp=unconfined", "-v", docker_volume_arg()]
    if interactive:
        cmd.append("-i")
    if name:
        cmd += ["--name", name]
    cmd += [AFL_IMAGE, "bash", "-c", inner]
    return cmd


def run_logged(cmd: list[str], ctx: RunContext, log_name: str, timeout: float | None = None,
               check: bool = True) -> int:
    """Запускает команду, весь её вывод пишет в logs/<run>/<log_name>."""
    ctx.log.info("exec: %s", " ".join(cmd))
    with open(ctx.logs / log_name, "a", encoding="utf-8", errors="replace") as out:
        proc = subprocess.run(cmd, stdout=out, stderr=subprocess.STDOUT, timeout=timeout)
    if proc.returncode != 0:
        msg = f"command failed rc={proc.returncode}: {' '.join(cmd)[:300]} (see {ctx.logs / log_name})"
        if check:
            ctx.log.error(msg)
            raise RuntimeError(msg)
        ctx.log.warning(msg)
    return proc.returncode


def build_targets(ctx: RunContext, which: str = "mini") -> None:
    """Сборка таргетов в контейнере (идемпотентно, быстро)."""
    script = {"mini": "/work/docker/build_mini.sh", "libpng": "/work/docker/build_libpng.sh"}[which]
    run_logged(docker_run_cmd(f"bash {script}"), ctx, f"build_{which}.log", timeout=3600)
