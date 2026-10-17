"""Рисование сети NEAT (SVG + PNG-кадр для GIF) и сборка GIF из кадров.
Входные нейроны всегда слева, выходные справа на одних и тех же местах во всех кадрах;
скрытые — по глубине (x) и детерминированному хэшу id (y), чтобы не «прыгали» между кадрами.
Цвет связи — знак веса, толщина — величина; отключённые связи — серый пунктир.

Собрать GIF заново из сохранённых кадров:  py -m neurofuzz.viz gif results/<run>
"""
from __future__ import annotations

import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.lines import Line2D  # noqa: E402

from .policy import INPUT_NAMES, OUTPUT_NAMES  # noqa: E402

# Цвета (палитра из references/palette.md skill dataviz): + синий, − красный, отключённые серые
POS, NEG, OFF = "#2a78d6", "#e34948", "#c3c2b7"
INK, MUTED, SURFACE = "#0b0b0b", "#898781", "#fcfcfb"
NODE_IN, NODE_HID, NODE_OUT = "#52514e", "#eb6834", "#1baf7a"


def complexity(genome) -> dict:
    """Число нейронов (скрытые + выходные, как в neat-python) и связей лучшей сети."""
    enabled = sum(1 for c in genome.connections.values() if c.enabled)
    hidden = sum(1 for k in genome.nodes if k >= len(OUTPUT_NAMES))
    return {"nodes": len(genome.nodes), "hidden": hidden, "connections": len(genome.connections),
            "enabled_connections": enabled}


def _depths(genome, input_keys, output_keys) -> dict[int, int]:
    """Глубина скрытых нейронов = длина самого длинного пути от входов (по всем связям)."""
    depth = {k: 0 for k in input_keys}
    hidden = [k for k in genome.nodes if k not in output_keys]
    for _ in range(len(hidden) + 1):
        changed = False
        for (a, b) in genome.connections:
            if a in depth and b in hidden:
                d = depth[a] + 1
                if depth.get(b, -1) < d and d <= len(hidden) + 1:
                    depth[b] = d
                    changed = True
        if not changed:
            break
    return {k: depth.get(k, 1) for k in hidden}


def layout(genome, config) -> dict[int, tuple[float, float]]:
    ins, outs = config.genome_config.input_keys, config.genome_config.output_keys
    pos = {}
    for i, k in enumerate(ins):
        pos[k] = (0.0, 1.0 - i / (len(ins) - 1))
    for i, k in enumerate(outs):
        pos[k] = (1.0, 0.9 - 0.8 * i / (len(outs) - 1))
    depths = _depths(genome, ins, outs)
    maxd = max(depths.values(), default=1)
    for k, d in depths.items():
        x = 0.25 + 0.5 * (d - 1) / max(maxd - 1, 1) if maxd > 1 else 0.5
        y = 0.05 + 0.9 * (((k * 2654435761) % 1000) / 1000.0)
        pos[k] = (x, y)
    return pos


def draw_genome(genome, config, svg_path: Path | None, png_path: Path | None = None,
                title: str = "") -> None:
    pos = layout(genome, config)
    fig, ax = plt.subplots(figsize=(10, 11), dpi=80)
    fig.patch.set_facecolor(SURFACE)
    ax.set_facecolor(SURFACE)
    ws = [abs(c.weight) for c in genome.connections.values() if c.enabled] or [1.0]
    wmax = max(max(ws), 1e-6)
    for (a, b), c in sorted(genome.connections.items(), key=lambda kv: kv[1].enabled):
        if a not in pos or b not in pos:
            continue
        (x1, y1), (x2, y2) = pos[a], pos[b]
        if c.enabled:
            lw = 0.4 + 3.6 * abs(c.weight) / wmax
            ax.plot([x1, x2], [y1, y2], color=POS if c.weight >= 0 else NEG, lw=lw, alpha=0.75,
                    solid_capstyle="round", zorder=1)
        else:
            ax.plot([x1, x2], [y1, y2], color=OFF, lw=0.8, ls=(0, (3, 3)), alpha=0.9, zorder=0)
    ins, outs = config.genome_config.input_keys, config.genome_config.output_keys
    used = {a for a, _ in genome.connections} | {b for _, b in genome.connections}
    for i, k in enumerate(ins):
        x, y = pos[k]
        ax.scatter([x], [y], s=60, color=NODE_IN if k in used else SURFACE, edgecolors=NODE_IN,
                   linewidths=1.2, zorder=3)
        ax.text(x - 0.02, y, INPUT_NAMES[i], ha="right", va="center", fontsize=7, color=MUTED)
    for i, k in enumerate(outs):
        x, y = pos[k]
        ax.scatter([x], [y], s=110, color=NODE_OUT, edgecolors=INK, linewidths=0.8, zorder=3)
        ax.text(x + 0.02, y, OUTPUT_NAMES[i], ha="left", va="center", fontsize=8, color=INK)
    hid = [k for k in genome.nodes if k not in outs]
    if hid:
        ax.scatter([pos[k][0] for k in hid], [pos[k][1] for k in hid], s=90, color=NODE_HID,
                   edgecolors=INK, linewidths=0.8, zorder=3)
    cx = complexity(genome)
    ax.set_title(title, fontsize=12, color=INK, loc="left")
    ax.text(0.0, -0.045, f"скрытых нейронов: {cx['hidden']}   связей: {cx['enabled_connections']} "
            f"активных / {cx['connections']} всего", fontsize=9, color=MUTED, transform=ax.transAxes)
    handles = [Line2D([], [], color=POS, lw=2.5, label="вес > 0"),
               Line2D([], [], color=NEG, lw=2.5, label="вес < 0"),
               Line2D([], [], color=OFF, lw=1, ls=(0, (3, 3)), label="отключённая связь"),
               Line2D([], [], marker="o", ls="", color=NODE_IN, label="вход"),
               Line2D([], [], marker="o", ls="", color=NODE_HID, label="скрытый"),
               Line2D([], [], marker="o", ls="", color=NODE_OUT, label="выход")]
    ax.legend(handles=handles, loc="upper center", bbox_to_anchor=(0.5, -0.06), ncol=6,
              frameon=False, fontsize=8, labelcolor=INK)
    # Фиксированные границы — входы/выходы на одних местах во всех кадрах
    ax.set_xlim(-0.16, 1.16)
    ax.set_ylim(-0.03, 1.03)
    ax.axis("off")
    fig.subplots_adjust(left=0.02, right=0.98, top=0.95, bottom=0.08)
    if svg_path:
        fig.savefig(svg_path, format="svg", facecolor=SURFACE)
    if png_path:
        fig.savefig(png_path, format="png", facecolor=SURFACE, dpi=60)  # кадр GIF — поменьше
    plt.close(fig)


def build_gif(frames_dir: Path, out_path: Path, ms_per_frame: int = 400) -> Path | None:
    """GIF из PNG-кадров (gen_XXXX.png) в порядке поколений; последний кадр держится дольше."""
    from PIL import Image

    frames = sorted(frames_dir.glob("gen_*.png"))
    if not frames:
        return None
    imgs = [Image.open(p).convert("P", palette=Image.ADAPTIVE, colors=128) for p in frames]
    durations = [ms_per_frame] * (len(imgs) - 1) + [2500]
    imgs[0].save(out_path, save_all=True, append_images=imgs[1:], duration=durations, loop=0,
                 optimize=True)
    return out_path


def main() -> None:
    if len(sys.argv) >= 3 and sys.argv[1] == "gif":
        run = Path(sys.argv[2])
        out = build_gif(run / "network" / "frames", run / "network" / "evolution.gif")
        print(f"[neurofuzz] GIF: {out}" if out else "[neurofuzz] ERROR: нет кадров")
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
