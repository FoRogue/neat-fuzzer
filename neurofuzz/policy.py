"""Политика мутаций на нейросети: как превратить состояние (покрытие родителя + байты входа)
в вектор входов сети и как превратить выходы сети в конкретную мутацию.
Здесь же — имена входов/выходов (подписи на схемах сети).
"""
from __future__ import annotations

import random

from .mutations import N_OPS, OP_NAMES, apply_op

N_COV_BUCKETS = 16      # bitmap 64 КБ сжимается в 16 корзин: edge_id % 16
N_BYTES = 24            # сеть видит первые 24 байта текущего входа
MAX_STACK = 8           # максимум мутаций, применяемых подряд к одному входу

INPUT_NAMES = ([f"cov{i}" for i in range(N_COV_BUCKETS)] + ["cov_frac", "fresh"] +
               [f"b{i}" for i in range(N_BYTES)] + ["len", "step", "rnd0", "rnd1"])
OUTPUT_NAMES = [f"op:{n}" for n in OP_NAMES] + ["pos", "val", "stack"]
N_INPUTS, N_OUTPUTS = len(INPUT_NAMES), len(OUTPUT_NAMES)   # 46, 11


def coverage_features(parent_edges, bucket_totals: list[int], global_edges: int) -> list[float]:
    """Сжатие карты покрытия родителя: для каждой корзины — доля известных рёбер корзины,
    которые проходит родитель; плюс доля всего глобального покрытия."""
    counts = [0] * N_COV_BUCKETS
    for e in parent_edges:
        counts[e % N_COV_BUCKETS] += 1
    feats = [c / t if t else 0.0 for c, t in zip(counts, bucket_totals)]
    feats.append(len(parent_edges) / global_edges if global_edges else 0.0)
    return feats


def bucket_totals(edges) -> list[int]:
    t = [0] * N_COV_BUCKETS
    for e in edges:
        t[e % N_COV_BUCKETS] += 1
    return t


def byte_features(buf: bytes) -> list[float]:
    """Байты -> [0,1]; отсутствующий байт (вход короче 24) = 0, присутствующий = (b+1)/256."""
    return [(buf[i] + 1) / 256.0 if i < len(buf) else 0.0 for i in range(N_BYTES)]


def network_mutate(net, parent, corpus, cov_feats: list[float], rng: random.Random,
                   op_counter: list[int] | None = None) -> bytes:
    """Одна «стопка» мутаций, выбранная сетью. Сеть вызывается на каждом шаге стопки и видит
    уже изменённые байты. Шум rnd0/rnd1 даёт сети возможность вести себя стохастически."""
    fresh = 1.0 / (1.0 + parent.picks)
    data = parent.data
    stack = 1
    k = 0
    while k < stack:
        x = cov_feats + [fresh] + byte_features(data) + [min(len(data) / 64.0, 1.0), k / MAX_STACK,
                                                          rng.random(), rng.random()]
        out = net.activate(x)
        if k == 0:
            stack = 1 + min(int(_unit(out[N_OPS + 2]) * MAX_STACK), MAX_STACK - 1)
        ops = out[:N_OPS]
        op = max(range(N_OPS), key=ops.__getitem__)
        if op_counter is not None:
            op_counter[op] += 1
        data = apply_op(data, op, _unit(out[N_OPS]), _unit(out[N_OPS + 1]), corpus, rng)
        k += 1
    return data


def _unit(v: float) -> float:
    """Выход сети -> [0,1). Активации бывают разными (sigmoid/tanh/relu/sin), поэтому clamp."""
    if v != v:  # NaN
        return 0.0
    return min(max(v, 0.0), 0.999999)
