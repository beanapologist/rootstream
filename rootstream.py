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

# The root constant: 1/√2, where everything started
ETA = 0.7071067811865476

# Default seed: IEEE 754 double of ETA, repeated to 32 bytes
def _make_default_seed() -> str:
    packed = struct.pack('<d', ETA).hex()
    return (packed * 4)[:64]

DEFAULT_SEED = _make_default_seed()


def stream(seed: str = DEFAULT_SEED) -> Iterator[bytes]:
    """
    Infinite deterministic byte stream from a root seed.

    Two machines with the same seed produce identical streams
    independently — no communication required after seed exchange.

    Args:
        seed: 64-char hex string (32 bytes). Default: derived from 1/√2.

    Yields:
        16-byte chunks indefinitely.

    Example:
        >>> gen = stream()
        >>> chunk = next(gen)
        >>> print(chunk.hex())
    """
    root = bytes.fromhex(seed)
    state = hashlib.sha256(root).digest()
    counter = 0

    while True:
        bits = []
        while len(bits) < 256:
            data = state + struct.pack('>I', counter)  # 4-byte big-endian uint32
            entropy = hashlib.sha256(data).digest()
            state = entropy
            counter += 1
            for byte in entropy:
                # sifting step: retain bit 0 when bits 1 and 2 match
                if ((byte >> 1) & 1) == ((byte >> 2) & 1):
                    bits.append(byte & 1)
                    if len(bits) >= 256:
                        break

        # XOR fold 256 bits -> 128 bits
        out = bytearray(16)
        for i in range(128):
            bit = bits[i] ^ bits[i + 128]
            out[i // 8] |= bit << (7 - (i % 8))

        yield bytes(out)


def floats(seed: str = DEFAULT_SEED) -> Iterator[float]:
    """
    Infinite stream of floats in [0, 1) from a root seed.

    Useful for generating coordinates, parameters, or any
    continuous value deterministically.

    Yields:
        float in [0, 1)
    """
    gen = stream(seed)
    buf = b""
    while True:
        while len(buf) < 8:
            buf += next(gen)
        value = struct.unpack('>Q', buf[:8])[0]
        buf = buf[8:]
        yield value / (2**64)


def seed_from(value: float) -> str:
    """
    Generate a 32-byte hex seed from any float (e.g. a mathematical constant).

    Args:
        value: Any float — ETA, PI, PHI, etc.

    Returns:
        64-char hex seed string.

    Example:
        >>> import math
        >>> s = seed_from(math.pi)
        >>> gen = stream(s)
    """
    packed = struct.pack('<d', value).hex()
    return (packed * 4)[:64]