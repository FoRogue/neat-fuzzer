"""Графики (matplotlib, SVG, подписи по-русски): покрытие и уникальные краши от времени для
нескольких фаззеров на одном графике, fitness по поколениям, сложность лучшей сети,
число исполнений от времени. Читают CSV из results/<run>/.

Перерисовать графики уже сделанного запуска:  py -m neurofuzz.plots results/<run>
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

# Фиксированное соответствие «фаззер -> цвет» (категориальная палитра skill dataviz, по порядку)
SERIES = {"afl": ("AFL++", "#2a78d6"), "neat": ("Нейрофаззер (NEAT)", "#eb6834"),
          "random": ("Случайные мутации", "#1baf7a")}
INK, MUTED, GRID, AXIS, SURFACE = "#0b0b0b", "#898781", "#e1e0d9", "#c3c2b7", "#fcfcfb"


def read_csv(path: Path) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def _style(ax, title: str, xlabel: str, ylabel: str) -> None:
    ax.set_title(title, fontsize=12, color=INK, loc="left")
    ax.set_xlabel(xlabel, color=MUTED)
    ax.set_ylabel(ylabel, color=MUTED)
    ax.set_facecolor(SURFACE)
    ax.grid(True, color=GRID, lw=0.6)
    ax.set_axisbelow(True)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color(AXIS)
    ax.tick_params(colors=MUTED)


def _fig():
    fig, ax = plt.subplots(figsize=(8, 4.5))
    fig.patch.set_facecolor(SURFACE)
    return fig, ax


def _save(fig, path: Path) -> Path:
    fig.tight_layout()
    fig.savefig(path, format="svg", facecolor=SURFACE)
    plt.close(fig)
    return path


def plot_timelines(timelines: dict[str, Path], column: str, title: str, ylabel: str,
                   out: Path) -> Path:
    """timelines: ключ фаззера (afl/neat/random) -> *_timeline.csv. Ступенчатые линии."""
    fig, ax = _fig()
    for key, path in timelines.items():
        rows = [r for r in read_csv(path) if r.get(column, "") != ""]  # у AFL начало без total_execs
        if not rows:
            continue
        name, color = SERIES.get(key, (key, MUTED))
        xs = [float(r["time_s"]) for r in rows]
        ys = [float(r[column]) for r in rows]
        ax.step(xs, ys, where="post", color=color, lw=2, label=name)
        ax.annotate(f"{ys[-1]:g}", (xs[-1], ys[-1]), xytext=(4, 0), textcoords="offset points",
                    va="center", fontsize=9, color=INK)
    _style(ax, title, "Время, с", ylabel)
    ax.set_ylim(bottom=0)
    ax.legend(frameon=False, labelcolor=INK)
    return _save(fig, out)


def plot_fitness(gen_csv: Path, out: Path) -> Path:
    rows = read_csv(gen_csv)
    g = [int(r["generation"]) for r in rows]
    fig, ax = _fig()
    ax.plot(g, [float(r["best_fitness"]) for r in rows], color="#2a78d6", lw=2, label="Лучший")
    ax.plot(g, [float(r["mean_fitness"]) for r in rows], color="#eb6834", lw=2, label="Средний")
    _style(ax, "Fitness по поколениям", "Поколение", "Fitness")
    ax.legend(frameon=False, labelcolor=INK)
    return _save(fig, out)


def plot_complexity(gen_csv: Path, out: Path) -> Path:
    """Число нейронов и связей лучшей сети — одна шкала (обе величины — штуки)."""
    rows = read_csv(gen_csv)
    g = [int(r["generation"]) for r in rows]
    fig, ax = _fig()
    ax.plot(g, [int(r["best_hidden"]) for r in rows], color="#eb6834", lw=2, label="Скрытые нейроны")
    ax.plot(g, [int(r["best_enabled_connections"]) for r in rows], color="#2a78d6", lw=2,
            label="Активные связи")
    _style(ax, "Сложность лучшей сети по поколениям", "Поколение", "Количество")
    ax.set_ylim(bottom=0)
    ax.legend(frameon=False, labelcolor=INK)
    return _save(fig, out)


def plot_run(run_dir: Path) -> list[Path]:
    """Все графики, для которых в папке запуска есть данные."""
    tl = {k: run_dir / k / f"{k}_timeline.csv" for k in SERIES}
    tl = {k: p for k, p in tl.items() if p.exists()}
    out = []
    plots = run_dir / "plots"
    plots.mkdir(exist_ok=True)
    if tl:
        out.append(plot_timelines(tl, "edges", "Покрытие кода от времени", "Покрыто рёбер (afl-showmap)",
                                  plots / "coverage_vs_time.svg"))
        out.append(plot_timelines(tl, "unique_crashes", "Уникальные краши от времени",
                                  "Уникальных крашей", plots / "crashes_vs_time.svg"))
        out.append(plot_timelines(tl, "total_execs", "Число запусков таргета от времени",
                                  "Исполнений", plots / "execs_vs_time.svg"))
    gen = run_dir / "neat" / "generations.csv"
    if gen.exists() and read_csv(gen):
        out.append(plot_fitness(gen, plots / "fitness_by_generation.svg"))
        out.append(plot_complexity(gen, plots / "network_complexity.svg"))
    return out


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
    else:
        for p in plot_run(Path(sys.argv[1])):
            print(f"[neurofuzz] {p}")
