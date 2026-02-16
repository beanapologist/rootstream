// Rootstream — from a single root to seed
// Rust Reference Implementation v1.0
//
// No dependencies — self-contained SHA-256.
// Build: rustc rootstream.rs -o rootstream
// Run:   ./rootstream
//
// NOT FOR CRYPTOGRAPHIC USE.

const K: [u32; 64] = [
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
];

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    let bit_len = (data.len() as u64) * 8;
    let mut m = data.to_vec();
    m.push(0x80);
    while m.len() % 64 != 56 {
        m.push(0x00);
    }
    for i in (0..8).rev() {
        m.push((bit_len >> (i * 8)) as u8);
    }

    let mut w = [0u32; 64];
    for block in m.chunks(64) {
        for j in 0..16 {
            w[j] = u32::from_be_bytes([block[j*4], block[j*4+1], block[j*4+2], block[j*4+3]]);
        }
        for j in 16..64 {
            let s0 = w[j-15].rotate_right(7) ^ w[j-15].rotate_right(18) ^ (w[j-15] >> 3);
            let s1 = w[j-2].rotate_right(17) ^ w[j-2].rotate_right(19)  ^ (w[j-2]  >> 10);
            w[j] = w[j-16].wrapping_add(s0).wrapping_add(w[j-7]).wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for j in 0..64 {
            let s1  = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch  = (e & f) ^ (!e & g);
            let t1  = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[j]).wrapping_add(w[j]);
            let s0  = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2  = s0.wrapping_add(maj);
            hh = g; g = f; f = e; e = d.wrapping_add(t1);
            d = c; c = b; b = a; a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a); h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c); h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e); h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g); h[7] = h[7].wrapping_add(hh);
    }

    let mut digest = [0u8; 32];
    for i in 0..8 {
        digest[i*4..i*4+4].copy_from_slice(&h[i].to_be_bytes());
    }
    digest
}

const ETA_BYTES: [u8; 8] = [0xcd, 0x3b, 0x7f, 0x66, 0x9e, 0xa0, 0xe6, 0x3f];

fn default_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    for i in 0..4 {
        seed[i*8..i*8+8].copy_from_slice(&ETA_BYTES);
    }
    seed
}

struct Rootstream {
    state: [u8; 32],
    counter: u32,
}

impl Rootstream {
    fn new(seed: &[u8; 32]) -> Self {
        Rootstream {
            state: sha256(seed),
            counter: 0,
        }
    }

    fn collect_bits(&mut self) -> Vec<u8> {
        let mut bits = Vec::with_capacity(256);

        while bits.len() < 256 {
            let mut data = [0u8; 36];
            data[..32].copy_from_slice(&self.state);
            data[32..].copy_from_slice(&self.counter.to_be_bytes());

            let entropy = sha256(&data);
            self.state = entropy;
            self.counter += 1;

            for b in &entropy {
                let bit1 = (b >> 1) & 1;
                let bit2 = (b >> 2) & 1;
                if bit1 == bit2 {
                    bits.push(b & 1);
                    if bits.len() >= 256 {
                        break;
                    }
                }
            }
        }

        bits
    }

    fn xor_fold(bits: &[u8]) -> [u8; 16] {
        let mut out = [0u8; 16];
        for i in 0..128 {
            let bit = bits[i] ^ bits[i + 128];
            out[i / 8] |= bit << (7 - (i % 8));
        }
        out
    }

    fn next(&mut self) -> [u8; 16] {
        let bits = self.collect_bits();
        Self::xor_fold(&bits)
    }
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

const EXPECTED: [&str; 5] = [
    "11ddfd55397330138a570f9f9c024996",
    "e17f659eabc361f9c6b20b68719bfa2d",
    "2286a6cba55b56a0ae5bffe3ab8618a6",
    "05e5ca4e66a018bc8cd87b417d49cfa4",
    "c8b25209a994b02cd0510c1f259f7448",
];

fn main() {
    println!("Rootstream — Rust Implementation");
    println!("Verifying against spec test vectors...\n");

    let seed = default_seed();
    let mut rs = Rootstream::new(&seed);
    let mut all_pass = true;

    for (i, expected) in EXPECTED.iter().enumerate() {
        let chunk = rs.next();
        let got = to_hex(&chunk);
        let pass = &got == expected;
        all_pass = all_pass && pass;

        println!("[{}]: {}  {}", i, if pass { "PASS" } else { "FAIL" }, got);
        if !pass {
            println!("  expected: {}", expected);
        }
    }

    println!();
    if all_pass {
        println!("✓ All vectors match. Implementation is compliant.");
    } else {
        println!("✗ Vectors do not match. Implementation is non-compliant.");
    }
}
