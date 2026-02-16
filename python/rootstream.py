"""
Rootstream — from a single root to seed

Deterministic byte stream generation from a shared root seed.
Two machines, same seed, identical streams. No data transmitted.

NOT FOR CRYPTOGRAPHY.
"""

from __future__ import annotations

import hashlib
import struct
from typing import Iterator

ETA = 0.7071067811865476

def _make_default_seed() -> str:
    packed = struct.pack('<d', ETA).hex()
    return (packed * 4)[:64]

DEFAULT_SEED = _make_default_seed()

def stream(seed: str = DEFAULT_SEED) -> Iterator[bytes]:
    root = bytes.fromhex(seed)
    state = hashlib.sha256(root).digest()
    counter = 0

    while True:
        bits = []
        while len(bits) < 256:
            data = state + struct.pack('>I', counter)
            entropy = hashlib.sha256(data).digest()
            state = entropy
            counter += 1
            for byte in entropy:
                if ((byte >> 1) & 1) == ((byte >> 2) & 1):
                    bits.append(byte & 1)
                    if len(bits) >= 256:
                        break

        out = bytearray(16)
        for i in range(128):
            bit = bits[i] ^ bits[i + 128]
            out[i // 8] |= bit << (7 - (i % 8))

        yield bytes(out)

def floats(seed: str = DEFAULT_SEED) -> Iterator[float]:
    gen = stream(seed)
    buf = b""
    while True:
        while len(buf) < 8:
            buf += next(gen)
        value = struct.unpack('>Q', buf[:8])[0]
        buf = buf[8:]
        yield value / (2**64)

def seed_from(value: float) -> str:
    packed = struct.pack('<d', value).hex()
    return (packed * 4)[:64]
