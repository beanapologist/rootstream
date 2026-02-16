# rootstream

*from a single root to seed*

A deterministic byte stream protocol. Two machines share a seed once. After that, they independently generate identical byte streams — no data transmitted.

Any compliant implementation in any language produces byte-for-byte identical output.

---

## The idea

Instead of sending data between machines, send a seed. Both sides reconstruct the same stream independently.

```
Machine A                    Machine B
─────────────────────        ─────────────────────
seed → stream chunk 0        seed → stream chunk 0  ← identical
seed → stream chunk 1        seed → stream chunk 1  ← identical
seed → stream chunk 2        seed → stream chunk 2  ← identical
```

One seed exchange. Zero ongoing bandwidth.

---

## Quick start

**Python**
```python
from rootstream import stream

gen = stream()
print(next(gen).hex())  # 11ddfd55397330138a570f9f9c024996
```

**C++**
```bash
g++ -std=c++17 -O2 rootstream.cpp -o rootstream
./rootstream
```

---

## Verify compliance

Any implementation must produce these exact outputs from the default seed:

```
[0]: 11ddfd55397330138a570f9f9c024996
[1]: e17f659eabc361f9c6b20b68719bfa2d
[2]: 2286a6cba55b56a0ae5bffe3ab8618a6
[3]: 05e5ca4e66a018bc8cd87b417d49cfa4
[4]: c8b25209a994b02cd0510c1f259f7448
```

If your implementation produces these vectors, it is compliant. See [SPEC.md](SPEC.md) for the full protocol.

---

## How it works

1. **Seed** — 32 bytes. Default is derived from η = 1/√2, the root constant the protocol is built on.
2. **State** — initialized as SHA-256 of the seed.
3. **Sifting** — repeatedly hash state + counter, collect bits where specific bit positions match.
4. **XOR fold** — compress 256 sifted bits into 128 bits (16 bytes) of output.
5. **Repeat** — infinite stream.

The sifting step and XOR fold are fully specified in [SPEC.md](SPEC.md) with no ambiguity. The test vectors are the ground truth.

---

## Custom seeds

```python
from rootstream import stream, seed_from
import math

# Any mathematical constant as a seed
gen = stream(seed_from(math.pi))
gen = stream(seed_from(math.e))
```

---

## What this is not

- **Not cryptography** — the stream is deterministic and reproducible. Do not use for passwords, keys, or secure channels.
- **Not compression** — the seed generates data, it does not encode it.

---

## Files

| File | Purpose |
|---|---|
| `SPEC.md` | Protocol specification and test vectors |
| `rootstream.py` | Python reference implementation |
| `rootstream.cpp` | C++ reference implementation (no dependencies) |

---

## Implementing in another language

Read [SPEC.md](SPEC.md). Implement the four steps. Run your output against the test vectors. If they match, you're done.

The most common mistake is encoding the counter wrong — it must be a 4-byte big-endian unsigned integer, not a string.

---

⚠️ NOT FOR CRYPTOGRAPHIC USE