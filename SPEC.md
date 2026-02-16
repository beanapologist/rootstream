# Rootstream Protocol Specification
**Version 1.0 — February 2026**

*from a single root to seed*

---

## Purpose

Rootstream is a deterministic byte stream protocol. Two machines that share
a seed will independently produce identical byte streams — no data transmitted
after seed exchange.

Any compliant implementation in any language must produce byte-for-byte
identical output given the same seed. The test vectors in this document
are the ground truth.

---

## Protocol

### Step 1 — Seed

The seed is exactly **32 bytes**, represented as a 64-character lowercase hex string.

The default seed is derived from η = 1/√2 ≈ 0.7071067811865476:
- Pack η as IEEE 754 double precision, little-endian: `cd3b7f669ea0e63f`
- Repeat 4 times to fill 32 bytes

```
DEFAULT_SEED = cd3b7f669ea0e63fcd3b7f669ea0e63fcd3b7f669ea0e63fcd3b7f669ea0e63f
```

Any 32-byte value may be used as a seed. The default seed is a reference point,
not a requirement.

---

### Step 2 — State Initialization

```
state = SHA-256(seed_bytes)
counter = 0
```

`state` is always 32 bytes. `counter` is a 32-bit unsigned integer, starting at 0.

---

### Step 3 — Sifting

Repeat until 256 bits are collected:

```
data    = state || uint32_be(counter)
entropy = SHA-256(data)
state   = entropy
counter = counter + 1

for each byte B in entropy:
    if bit1(B) == bit2(B):          // (B >> 1) & 1 == (B >> 2) & 1
        append bit0(B) to sifted    // B & 1
        if len(sifted) == 256: stop
```

**Critical implementation details:**
- `uint32_be(counter)` — counter is encoded as exactly **4 bytes, big-endian unsigned integer**
- `||` denotes concatenation: 32 bytes of state followed by 4 bytes of counter = 36 bytes total
- `bit0` is the least significant bit: `B & 1`
- `bit1` is the next bit: `(B >> 1) & 1`
- `bit2` is the next bit: `(B >> 2) & 1`
- Collect exactly 256 bits, no more

---

### Step 4 — XOR Fold

Compress 256 sifted bits into 128 bits:

```
for i = 0 to 127:
    out_bit[i] = sifted[i] XOR sifted[i + 128]
```

Pack `out_bit` into 16 bytes, **MSB first** (bit 0 of output is the most significant
bit of byte 0):

```
byte[k] = out_bit[k*8] << 7
        | out_bit[k*8+1] << 6
        | out_bit[k*8+2] << 5
        | out_bit[k*8+3] << 4
        | out_bit[k*8+4] << 3
        | out_bit[k*8+5] << 2
        | out_bit[k*8+6] << 1
        | out_bit[k*8+7]
```

Yield these 16 bytes as one output chunk.

---

### Step 5 — Continue

Return to Step 3 with the updated `state` and `counter`. The stream is infinite.

---

## Test Vectors

Given `DEFAULT_SEED`, the first 5 output chunks must be exactly:

```
Initial state: c446e7326bf573c1f62e9b15a0df25facc10be1f03cf6f4e2d021f0cce5e05ac

[0]: 11ddfd55397330138a570f9f9c024996
[1]: e17f659eabc361f9c6b20b68719bfa2d
[2]: 2286a6cba55b56a0ae5bffe3ab8618a6
[3]: 05e5ca4e66a018bc8cd87b417d49cfa4
[4]: c8b25209a994b02cd0510c1f259f7448
```

Any implementation that produces these vectors is compliant.
Any implementation that does not is incorrect.

---

## Common Mistakes

| Mistake | Symptom |
|---|---|
| Counter as UTF-8 string (`"0"`, `"1"`) | Diverges from vector [0] immediately |
| Counter as little-endian int | Diverges from vector [0] immediately |
| LSB-first bit packing | All vectors wrong |
| SHA-256 of seed directly as first entropy | Diverges at vector [0] |
| Collecting != 256 bits | Diverges at vector [0] |

---

## Reference Constants

Other seeds derived from mathematical constants:

```
ETA  = 1/√2  → cd3b7f669ea0e63f... (default)
PHI  = 1.618033988749895 → IEEE 754 LE, repeated
PI   = 3.141592653589793 → IEEE 754 LE, repeated  
E    = 2.718281828459045 → IEEE 754 LE, repeated
```

All seeds follow the same pattern: 8-byte IEEE 754 little-endian double, repeated 4 times.

---

## What Rootstream Is Not

- Not a cryptographic protocol — do not use for passwords, keys, or secure channels
- Not a compression algorithm — the seed does not encode the data, it generates it
- Not quantum — the "sifting" step is a deterministic filter, not quantum measurement

---

*Rootstream v1.0 — implementations welcome in any language*