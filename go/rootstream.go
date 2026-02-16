// Rootstream — from a single root to seed
// Go Reference Implementation v1.0
//
// Uses stdlib crypto/sha256 — no external dependencies.
// Build: go build -o rootstream rootstream.go
// Run:   ./rootstream
//
// NOT FOR CRYPTOGRAPHIC USE.

package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
)

const eta = 0.7071067811865476 // η = 1/√2

func seedFrom(value float64) [32]byte {
	var seed [32]byte
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], math.Float64bits(value))
	for i := 0; i < 4; i++ {
		copy(seed[i*8:], buf[:])
	}
	return seed
}

func defaultSeed() [32]byte {
	return seedFrom(eta)
}

type Rootstream struct {
	state   [32]byte
	counter uint32
}

func NewRootstream(seed [32]byte) *Rootstream {
	return &Rootstream{
		state:   sha256.Sum256(seed[:]),
		counter: 0,
	}
}

func (rs *Rootstream) collectBits() []byte {
	bits := make([]byte, 0, 256)

	for len(bits) < 256 {
		var data [36]byte
		copy(data[:32], rs.state[:])
		binary.BigEndian.PutUint32(data[32:], rs.counter)

		entropy := sha256.Sum256(data[:])
		rs.state = entropy
		rs.counter++

		for _, b := range entropy {
			bit1 := (b >> 1) & 1
			bit2 := (b >> 2) & 1
			if bit1 == bit2 {
				bits = append(bits, b&1)
				if len(bits) >= 256 {
					break
				}
			}
		}
	}

	return bits
}

func xorFold(bits []byte) [16]byte {
	var out [16]byte
	for i := 0; i < 128; i++ {
		bit := bits[i] ^ bits[i+128]
		out[i/8] |= bit << (7 - (i % 8))
	}
	return out
}

func (rs *Rootstream) Next() [16]byte {
	bits := rs.collectBits()
	return xorFold(bits)
}

var expected = []string{
	"11ddfd55397330138a570f9f9c024996",
	"e17f659eabc361f9c6b20b68719bfa2d",
	"2286a6cba55b56a0ae5bffe3ab8618a6",
	"05e5ca4e66a018bc8cd87b417d49cfa4",
	"c8b25209a994b02cd0510c1f259f7448",
}

func main() {
	fmt.Println("Rootstream — Go Implementation")
	fmt.Println("Verifying against spec test vectors...")
	fmt.Println()

	seed := defaultSeed()
	rs := NewRootstream(seed)
	allPass := true

	for i, exp := range expected {
		chunk := rs.Next()
		got := hex.EncodeToString(chunk[:])
		pass := got == exp
		allPass = allPass && pass

		status := "PASS"
		if !pass {
			status = "FAIL"
		}
		fmt.Printf("[%d]: %s  %s\n", i, status, got)
		if !pass {
			fmt.Printf("  expected: %s\n", exp)
		}
	}

	fmt.Println()
	if allPass {
		fmt.Println("✓ All vectors match. Implementation is compliant.")
	} else {
		fmt.Println("✗ Vectors do not match. Implementation is non-compliant.")
	}
}
