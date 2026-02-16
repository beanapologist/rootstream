/*
 * Rootstream — from a single root to seed
 * JavaScript Reference Implementation v1.0
 *
 * Runs in Node.js, Deno, Bun, and browsers.
 * No dependencies — self-contained SHA-256.
 *
 * NOT FOR CRYPTOGRAPHIC USE.
 *
 * Verify against test vectors in SPEC.md before using.
 */

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function rotr(x, n) {
  return (x >>> n) | (x << (32 - n));
}

function sha256(data) {
  let h = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ]);

  const bitLen = data.length * 8;
  const padLen = data.length % 64 < 56 ? 56 - (data.length % 64) : 120 - (data.length % 64);
  const m = new Uint8Array(data.length + padLen + 8);
  m.set(data);
  m[data.length] = 0x80;
  const dv = new DataView(m.buffer);
  dv.setUint32(m.length - 4, bitLen >>> 0, false);

  const w = new Uint32Array(64);
  for (let i = 0; i < m.length; i += 64) {
    for (let j = 0; j < 16; j++)
      w[j] = dv.getUint32(i + j * 4, false);
    for (let j = 16; j < 64; j++) {
      const s0 = rotr(w[j-15], 7) ^ rotr(w[j-15], 18) ^ (w[j-15] >>> 3);
      const s1 = rotr(w[j-2], 17) ^ rotr(w[j-2], 19)  ^ (w[j-2]  >>> 10);
      w[j] = (w[j-16] + s0 + w[j-7] + s1) >>> 0;
    }

    let [a, b, c, d, e, f, g, hh] = h;
    for (let j = 0; j < 64; j++) {
      const S1  = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch  = (e & f) ^ (~e & g);
      const t1  = (hh + S1 + ch + K[j] + w[j]) >>> 0;
      const S0  = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2  = (S0 + maj) >>> 0;
      hh = g; g = f; f = e; e = (d + t1) >>> 0;
      d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0;
    h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0;
    h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0;
    h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0;
  }

  const digest = new Uint8Array(32);
  const out = new DataView(digest.buffer);
  for (let i = 0; i < 8; i++) out.setUint32(i * 4, h[i], false);
  return digest;
}

const ETA_BYTES = new Uint8Array([0xcd, 0x3b, 0x7f, 0x66, 0x9e, 0xa0, 0xe6, 0x3f]);
const DEFAULT_SEED = new Uint8Array(32);
for (let i = 0; i < 4; i++) DEFAULT_SEED.set(ETA_BYTES, i * 8);

class Rootstream {
  constructor(seed = DEFAULT_SEED) {
    this.state = sha256(seed);
    this.counter = 0;
  }

  _collectBits() {
    const bits = [];
    const counterBuf = new Uint8Array(4);
    const dv = new DataView(counterBuf.buffer);

    while (bits.length < 256) {
      dv.setUint32(0, this.counter, false);
      const data = new Uint8Array(36);
      data.set(this.state, 0);
      data.set(counterBuf, 32);

      const entropy = sha256(data);
      this.state = entropy;
      this.counter++;

      for (const b of entropy) {
        const bit1 = (b >> 1) & 1;
        const bit2 = (b >> 2) & 1;
        if (bit1 === bit2) {
          bits.push(b & 1);
          if (bits.length >= 256) break;
        }
      }
    }

    return bits;
  }

  _xorFold(bits) {
    const out = new Uint8Array(16);
    for (let i = 0; i < 128; i++) {
      const bit = bits[i] ^ bits[i + 128];
      out[Math.floor(i / 8)] |= bit << (7 - (i % 8));
    }
    return out;
  }

  next() {
    return this._xorFold(this._collectBits());
  }

  *[Symbol.iterator]() {
    while (true) yield this.next();
  }
}

function toHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

const EXPECTED = [
  "11ddfd55397330138a570f9f9c024996",
  "e17f659eabc361f9c6b20b68719bfa2d",
  "2286a6cba55b56a0ae5bffe3ab8618a6",
  "05e5ca4e66a018bc8cd87b417d49cfa4",
  "c8b25209a994b02cd0510c1f259f7448",
];

function runTests() {
  console.log("Rootstream — JavaScript Implementation");
  console.log("Verifying against spec test vectors...\n");

  const rs = new Rootstream();
  let allPass = true;

  for (let i = 0; i < 5; i++) {
    const got = toHex(rs.next());
    const pass = got === EXPECTED[i];
    allPass = allPass && pass;
    console.log(`[${i}]: ${pass ? "PASS" : "FAIL"}  ${got}`);
    if (!pass) console.log(`  expected: ${EXPECTED[i]}`);
  }

  console.log();
  console.log(allPass
    ? "✓ All vectors match. Implementation is compliant."
    : "✗ Vectors do not match. Implementation is non-compliant."
  );
}

if (typeof require !== "undefined" && require.main === module) {
  runTests();
}
