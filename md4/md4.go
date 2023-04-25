package md4

import (
	"encoding/binary"
	"math/bits"
)

const (
	_r0 = 0x67452301
	_r1 = 0xEFCDAB89
	_r2 = 0x98BADCFE
	_r3 = 0x10325476
)

// The size of an MD4 message digest in bytes.
const Size = 16

// The blocksize of MD4 in bytes.
const BlockSize = 64

// Digest is an MD4 message digest.
type Digest [Size]byte

// Sum returns the MD4 checksum of message.
//
// A proper implementation exists in golang.org/x/crypto/md4. This was written
// as a learning exercise.
func Sum(message []byte) Digest {
	r := [4]uint32{_r0, _r1, _r2, _r3}
	return SumFromHashState(r, 0, message)
}

// SumFromHashState returns the MD4 checksum of the data starting from an
// initial state of the hash registers, r, and an initial message byte length,
// initLen. The message bit length written to the padding is
// (initLen + len(data)) * 8.
func SumFromHashState(r [4]uint32, initLen uint64, data []byte) Digest {
	dataLen := len(data)
	padLen := BlockSize - (dataLen % BlockSize)
	if padLen < 9 {
		padLen += BlockSize
	}

	m := make([]byte, dataLen+padLen)
	copy(m, data)
	m[dataLen] = 0x80
	binary.LittleEndian.PutUint64(m[len(m)-8:], (initLen+uint64(dataLen))*8)

	var (
		a = r[0]
		b = r[1]
		c = r[2]
		d = r[3]
	)

	var x [16]uint32
	for ; len(m) >= BlockSize; m = m[BlockSize:] {
		for i, j := 0, 0; i < 16; i, j = i+1, j+4 {
			x[i] = binary.LittleEndian.Uint32(m[j : j+4])
		}

		var (
			aa = a
			bb = b
			cc = c
			dd = d
		)

		// Round 1.
		a = ff(a, b, c, d, x[0], 3)
		d = ff(d, a, b, c, x[1], 7)
		c = ff(c, d, a, b, x[2], 11)
		b = ff(b, c, d, a, x[3], 19)
		a = ff(a, b, c, d, x[4], 3)
		d = ff(d, a, b, c, x[5], 7)
		c = ff(c, d, a, b, x[6], 11)
		b = ff(b, c, d, a, x[7], 19)
		a = ff(a, b, c, d, x[8], 3)
		d = ff(d, a, b, c, x[9], 7)
		c = ff(c, d, a, b, x[10], 11)
		b = ff(b, c, d, a, x[11], 19)
		a = ff(a, b, c, d, x[12], 3)
		d = ff(d, a, b, c, x[13], 7)
		c = ff(c, d, a, b, x[14], 11)
		b = ff(b, c, d, a, x[15], 19)

		// Round 2.
		a = gg(a, b, c, d, x[0], 3)
		d = gg(d, a, b, c, x[4], 5)
		c = gg(c, d, a, b, x[8], 9)
		b = gg(b, c, d, a, x[12], 13)
		a = gg(a, b, c, d, x[1], 3)
		d = gg(d, a, b, c, x[5], 5)
		c = gg(c, d, a, b, x[9], 9)
		b = gg(b, c, d, a, x[13], 13)
		a = gg(a, b, c, d, x[2], 3)
		d = gg(d, a, b, c, x[6], 5)
		c = gg(c, d, a, b, x[10], 9)
		b = gg(b, c, d, a, x[14], 13)
		a = gg(a, b, c, d, x[3], 3)
		d = gg(d, a, b, c, x[7], 5)
		c = gg(c, d, a, b, x[11], 9)
		b = gg(b, c, d, a, x[15], 13)

		// Round 3.
		a = hh(a, b, c, d, x[0], 3)
		d = hh(d, a, b, c, x[8], 9)
		c = hh(c, d, a, b, x[4], 11)
		b = hh(b, c, d, a, x[12], 15)
		a = hh(a, b, c, d, x[2], 3)
		d = hh(d, a, b, c, x[10], 9)
		c = hh(c, d, a, b, x[6], 11)
		b = hh(b, c, d, a, x[14], 15)
		a = hh(a, b, c, d, x[1], 3)
		d = hh(d, a, b, c, x[9], 9)
		c = hh(c, d, a, b, x[5], 11)
		b = hh(b, c, d, a, x[13], 15)
		a = hh(a, b, c, d, x[3], 3)
		d = hh(d, a, b, c, x[11], 9)
		c = hh(c, d, a, b, x[7], 11)
		b = hh(b, c, d, a, x[15], 15)

		a += aa
		b += bb
		c += cc
		d += dd
	}

	var md [Size]byte
	binary.LittleEndian.PutUint32(md[0:], a)
	binary.LittleEndian.PutUint32(md[4:], b)
	binary.LittleEndian.PutUint32(md[8:], c)
	binary.LittleEndian.PutUint32(md[12:], d)

	return md
}

func ff(a, b, c, d, x uint32, s int) uint32 {
	f := (b & c) | (^b & d)
	return bits.RotateLeft32((a + f + x), s)
}

func gg(a, b, c, d, x uint32, s int) uint32 {
	g := (b & c) | (b & d) | (c & d)
	return bits.RotateLeft32((a + g + x + 0x5A827999), s)
}

func hh(a, b, c, d, x uint32, s int) uint32 {
	h := b ^ c ^ d
	return bits.RotateLeft32((a + h + x + 0x6ED9EBA1), s)
}
