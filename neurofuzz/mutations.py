"""Операторы мутаций входных байтов. Общие для нейрофаззера (сеть выбирает оператор,
позицию и значение) и для случайного фаззера (havoc — случайная стопка операторов, как в AFL).
"""
from __future__ import annotations

import random

MAX_LEN = 4096
INTERESTING = [0, 1, 0x7f, 0x80, 0xff, 0x10, 0x20, 0x40, 0x64, 0x7fff, 0x8000, 0xffff,
               0x7fffffff, 0x80000000, 0xffffffff, ord("0"), ord("9"), ord("A"), ord("Z")]

# Имена операторов в том же порядке, что выходы сети (op_0..op_N-1)
OP_NAMES = ["bitflip", "set_byte", "insert_byte", "delete_byte", "interesting", "arith",
            "clone_block", "splice"]
N_OPS = len(OP_NAMES)


def apply_op(data: bytes, op: int, pos_f: float, val_f: float, corpus=None,
             rng: random.Random | None = None) -> bytes:
    """Применить оператор op. pos_f, val_f в [0,1] — позиция и «значение» (от сети или случайные)."""
    buf = bytearray(data)
    n = len(buf)
    pos = min(int(pos_f * n), n - 1) if n else 0
    val = min(int(val_f * 256), 255)
    if op == 0 and n:                                   # инвертировать бит
        buf[pos] ^= 1 << (val % 8)
    elif op == 1 and n:                                 # записать байт
        buf[pos] = val
    elif op == 2 and n < MAX_LEN:                       # вставить байт
        buf.insert(min(int(pos_f * (n + 1)), n), val)
    elif op == 3 and n > 1:                             # удалить байт
        del buf[pos]
    elif op == 4 and n:                                 # «интересное» значение (1/2/4 байта LE)
        v = INTERESTING[int(val_f * len(INTERESTING)) % len(INTERESTING)]
        width = 1 if v < 0x100 else (2 if v < 0x10000 else 4)
        chunk = v.to_bytes(width, "little")
        buf[pos:pos + width] = chunk
    elif op == 5 and n:                                 # прибавить/вычесть -35..35
        buf[pos] = (buf[pos] + int(val_f * 71) - 35) & 0xff
    elif op == 6 and n and n < MAX_LEN:                 # скопировать блок в другое место
        ln = max(1, int(val_f * min(32, n)))
        src = buf[pos:pos + ln]
        dst = (pos * 7 + ln) % (n + 1)
        buf[dst:dst] = src
    elif op == 7 and corpus:                            # склейка с другим входом корпуса
        other = corpus[int(val_f * len(corpus)) % len(corpus)].data
        cut = pos
        buf = buf[:cut] + bytearray(other[min(cut, len(other)):])
    if not buf:
        buf = bytearray(b"\x00")
    return bytes(buf[:MAX_LEN])


def havoc(data: bytes, rng: random.Random, corpus=None, max_stack: int = 8) -> bytes:
    """Случайная стопка из 1..max_stack операторов — эталон «без нейросети»."""
    for _ in range(1 << rng.randint(0, max_stack.bit_length() - 1)):
        data = apply_op(data, rng.randrange(N_OPS), rng.random(), rng.random(), corpus, rng)
    return data
