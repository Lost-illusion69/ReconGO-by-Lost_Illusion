// Package mmh3 implements 32-bit MurmurHash3 (x86) compatible with Python mmh3
// and Shodan's favicon / http.body hash format (signed int32).
package mmh3

import "encoding/binary"

const (
	c1 = 0xcc9e2d51
	c2 = 0x1b873593
)

// Hash computes the 32-bit MurmurHash3 digest of data with seed 0, returning
// a signed int32 matching Python mmh3.hash(data).
func Hash(data []byte) int32 {
	return HashSeed(data, 0)
}

// HashString computes Hash over the UTF-8 bytes of s.
func HashString(s string) int32 {
	return Hash([]byte(s))
}

// HashSeed computes MurmurHash3 x86 32-bit with the given seed.
func HashSeed(data []byte, seed uint32) int32 {
	length := len(data)
	h1 := seed
	nblocks := length / 4

	for i := 0; i < nblocks; i++ {
		k1 := binary.LittleEndian.Uint32(data[i*4 : (i+1)*4])
		k1 *= c1
		k1 = rotl32(k1, 15)
		k1 *= c2

		h1 ^= k1
		h1 = rotl32(h1, 13)
		h1 = h1*5 + 0xe6546b64
	}

	tail := data[nblocks*4:]
	var k1 uint32
	switch len(tail) {
	case 3:
		k1 ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(tail[0])
		k1 *= c1
		k1 = rotl32(k1, 15)
		k1 *= c2
		h1 ^= k1
	}

	h1 ^= uint32(length)
	h1 = fmix32(h1)
	return int32(h1)
}

func rotl32(x uint32, r uint8) uint32 {
	return (x << r) | (x >> (32 - r))
}

func fmix32(h uint32) uint32 {
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return h
}
