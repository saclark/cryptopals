package sha1

import (
	"encoding/binary"
	"math/bits"
)

const (
	_h0 = 0x67452301
	_h1 = 0xEFCDAB89
	_h2 = 0x98BADCFE
	_h3 = 0x10325476
	_h4 = 0xC3D2E1F0

	_k0 = 0x5A827999
	_k1 = 0x6ED9EBA1
	_k2 = 0x8F1BBCDC
	_k3 = 0xCA62C1D6
)

// The size of a SHA-1 message digest in bytes.
const Size = 20

// The blocksize of SHA-1 in bytes.
const BlockSize = 64

// Digest is a SHA-1 message digest.
type Digest [Size]byte

// Sum returns the SHA-1 checksum of message.
//
// A proper implementation exists in the Go standard library. This was written
// as a learning exercise.
func Sum(message []byte) Digest {
	msgLen := len(message)
	padLen := BlockSize - (msgLen % BlockSize)
	if padLen < 9 {
		padLen += BlockSize
	}

	m := make([]byte, msgLen+padLen)
	copy(m, message)
	m[msgLen] = 0x80
	binary.BigEndian.PutUint64(m[len(m)-8:], uint64(msgLen)*8)

	h := [5]uint32{_h0, _h1, _h2, _h3, _h4}

	var w [80]uint32
	for ; len(m) >= BlockSize; m = m[BlockSize:] {
		for i, j := 0, 0; i < 16; i, j = i+1, j+4 {
			w[i] = binary.BigEndian.Uint32(m[j : j+4])
		}

		for t := 16; t < 80; t++ {
			w[t] = bits.RotateLeft32((w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16]), 1)
		}

		var (
			a = h[0]
			b = h[1]
			c = h[2]
			d = h[3]
			e = h[4]
		)

		var f, k uint32
		for t := 0; t < 80; t++ {
			switch {
			case t < 20:
				f = (b & c) | (^b & d)
				k = _k0
			case t < 40:
				f = b ^ c ^ d
				k = _k1
			case t < 60:
				f = (b & c) | (b & d) | (c & d)
				k = _k2
			case t < 80:
				f = b ^ c ^ d
				k = _k3
			}

			tmp := (bits.RotateLeft32(a, 5) + f + e + w[t] + k)

			e = d
			d = c
			c = bits.RotateLeft32(b, 30)
			b = a
			a = tmp
		}

		h[0] += a
		h[1] += b
		h[2] += c
		h[3] += d
		h[4] += e
	}

	var md Digest
	binary.BigEndian.PutUint32(md[0:], h[0])
	binary.BigEndian.PutUint32(md[4:], h[1])
	binary.BigEndian.PutUint32(md[8:], h[2])
	binary.BigEndian.PutUint32(md[12:], h[3])
	binary.BigEndian.PutUint32(md[16:], h[4])

	return md
}
