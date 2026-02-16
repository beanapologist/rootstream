/*
 * Rootstream — from a single root to seed
 * C++ Reference Implementation v1.0
 *
 * Produces byte-for-byte identical output to any compliant implementation.
 * Verify against test vectors in SPEC.md before using.
 *
 * No dependencies — self-contained SHA-256 implementation.
 * Build: g++ -std=c++17 -O2 rootstream.cpp -o rootstream
 */

#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <string>
#include <cstdint>
#include <cstring>

using Bytes = std::vector<uint8_t>;

static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
};

static inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

Bytes sha256(const Bytes& msg) {
    uint32_t h[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19,
    };

    Bytes m = msg;
    uint64_t bit_len = (uint64_t)msg.size() * 8;
    m.push_back(0x80);
    while (m.size() % 64 != 56) m.push_back(0x00);
    for (int i = 7; i >= 0; --i) m.push_back((bit_len >> (i * 8)) & 0xff);

    for (size_t i = 0; i < m.size(); i += 64) {
        uint32_t w[64];
        for (int j = 0; j < 16; ++j)
            w[j] = ((uint32_t)m[i+j*4] << 24) | ((uint32_t)m[i+j*4+1] << 16)
                 | ((uint32_t)m[i+j*4+2] << 8) | m[i+j*4+3];
        for (int j = 16; j < 64; ++j) {
            uint32_t s0 = rotr(w[j-15],7) ^ rotr(w[j-15],18) ^ (w[j-15] >> 3);
            uint32_t s1 = rotr(w[j-2],17) ^ rotr(w[j-2],19)  ^ (w[j-2] >> 10);
            w[j] = w[j-16] + s0 + w[j-7] + s1;
        }

        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for (int j = 0; j < 64; ++j) {
            uint32_t S1  = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
            uint32_t ch  = (e & f) ^ (~e & g);
            uint32_t t1  = hh + S1 + ch + K[j] + w[j];
            uint32_t S0  = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2  = S0 + maj;
            hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d;
        h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }

    Bytes digest(32);
    for (int i = 0; i < 8; ++i) {
        digest[i*4]   = (h[i] >> 24) & 0xff;
        digest[i*4+1] = (h[i] >> 16) & 0xff;
        digest[i*4+2] = (h[i] >>  8) & 0xff;
        digest[i*4+3] =  h[i]        & 0xff;
    }
    return digest;
}

Bytes default_seed() {
    uint8_t eta_bytes[8] = {0xcd, 0x3b, 0x7f, 0x66, 0x9e, 0xa0, 0xe6, 0x3f};
    Bytes seed;
    for (int i = 0; i < 4; ++i)
        for (int j = 0; j < 8; ++j)
            seed.push_back(eta_bytes[j]);
    return seed;
}

struct Rootstream {
    Bytes state;
    uint32_t counter;

    explicit Rootstream(const Bytes& seed) {
        state = sha256(seed);
        counter = 0;
    }

    std::vector<int> collect_bits() {
        std::vector<int> bits;
        bits.reserve(256);

        while (bits.size() < 256) {
            Bytes data = state;
            data.push_back((counter >> 24) & 0xff);
            data.push_back((counter >> 16) & 0xff);
            data.push_back((counter >>  8) & 0xff);
            data.push_back((counter      ) & 0xff);

            Bytes entropy = sha256(data);
            state = entropy;
            counter++;

            for (uint8_t b : entropy) {
                uint8_t bit1 = (b >> 1) & 1;
                uint8_t bit2 = (b >> 2) & 1;
                if (bit1 == bit2) {
                    bits.push_back(b & 1);
                    if (bits.size() >= 256) break;
                }
            }
        }

        return bits;
    }

    Bytes xor_fold(const std::vector<int>& bits) {
        Bytes out(16, 0);
        for (int i = 0; i < 128; ++i) {
            int bit = bits[i] ^ bits[i + 128];
            out[i / 8] |= bit << (7 - (i % 8));
        }
        return out;
    }

    Bytes next() {
        auto bits = collect_bits();
        return xor_fold(bits);
    }
};

std::string to_hex(const Bytes& b) {
    std::ostringstream ss;
    for (uint8_t byte : b)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    return ss.str();
}

const char* EXPECTED[] = {
    "11ddfd55397330138a570f9f9c024996",
    "e17f659eabc361f9c6b20b68719bfa2d",
    "2286a6cba55b56a0ae5bffe3ab8618a6",
    "05e5ca4e66a018bc8cd87b417d49cfa4",
    "c8b25209a994b02cd0510c1f259f7448",
};

void run_tests() {
    std::cout << "Rootstream — C++ Implementation\n";
    std::cout << "Verifying against spec test vectors...\n\n";

    Rootstream rs(default_seed());
    bool all_pass = true;

    for (int i = 0; i < 5; ++i) {
        auto chunk = rs.next();
        std::string got = to_hex(chunk);
        bool pass = (got == EXPECTED[i]);
        all_pass = all_pass && pass;

        std::cout << "[" << i << "]: " << (pass ? "PASS" : "FAIL")
                  << "  " << got << "\n";

        if (!pass)
            std::cout << "  expected: " << EXPECTED[i] << "\n";
    }

    std::cout << "\n";
    if (all_pass)
        std::cout << "✓ All vectors match. Implementation is compliant.\n";
    else
        std::cout << "✗ Vectors do not match. Implementation is non-compliant.\n";
}

int main() {
    run_tests();
    return 0;
}
