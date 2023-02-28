package xor

import "math/bits"

// Relative frequencies among A-Z (case insensitive) and "space" characters in
// the english language listed in the order [A, B, ..., Z, space].
// See: https://web.archive.org/web/20170918020907/http://www.data-compression.com/english.html
var relEngCharFreqs = []float64{
	0.0651738, 0.0124248, 0.0217339, 0.0349835, 0.1041442, 0.0197881, 0.0158610,
	0.0492888, 0.0558094, 0.0009033, 0.0050529, 0.0331490, 0.0202124, 0.0564513,
	0.0596302, 0.0137645, 0.0008606, 0.0497563, 0.0515760, 0.0729357, 0.0225134,
	0.0082903, 0.0171272, 0.0013692, 0.0145984, 0.0007836,
	0.1918182, // space
}

// scoreEnglishLikeness scores the likelihood that s represents english text.
// The score is normalized according to the length of s but the shorter s is the
// less meaningful the result is likely to be.
func scoreEnglishLikeness(s []byte) float64 {
	var score float64
	for _, b := range s {
		switch {
		case b >= 'A' && b <= 'Z':
			score += relEngCharFreqs[b-'A']
		case b >= 'a' && b <= 'z':
			score += relEngCharFreqs[b-'a']
		case b == ' ':
			score += relEngCharFreqs[len(relEngCharFreqs)-1]
		}
	}
	return score / float64(len(s))
}

// scoreRepeatingKeySize scores the likelihood that a given ciphertext was
// produced by XOR-ing keySize byte blocks of the plaintext with the same
// keySize byte key. The lower the score the more likely.
func scoreRepeatingKeySize(ciphertext []byte, keySize int) float64 {
	if keySize <= 0 {
		panic("xor.scoreRepeatingKeySize: keysize not > 0")
	}
	if len(ciphertext) <= keySize || len(ciphertext)%keySize != 0 {
		panic("xor.scoreRepeatingKeySize: ciphertext size not multiple of key size > key size")
	}

	var dist int
	n := len(ciphertext)/keySize - 1
	for i := 0; i < n; i++ {
		l, m, h := keySize*i, keySize*(i+1), keySize*(i+2)
		dist += hammingDistance(ciphertext[l:m], ciphertext[m:h])
	}

	return float64(dist) / float64(n) / float64(keySize)
}

func hammingDistance(a, b []byte) int {
	if len(a) != len(b) {
		panic("xor.hammingDistance: a and b not same length")
	}
	var dist int
	for i := 0; i < len(a); i++ {
		dist += bits.OnesCount8(a[i] ^ b[i])
	}
	return dist
}

// transposeBlocks partitions s into blockSize byte blocks and then transposes
// those blocks.
func transposeBlocks(s []byte, blockSize int) [][]byte {
	if blockSize <= 0 {
		panic("xor.transposeBlocks: blockSize not > 0")
	}
	result := make([][]byte, minInt(len(s), blockSize))
	for i := 0; i < blockSize; i++ {
		for j := i; j < len(s); j += blockSize {
			result[i] = append(result[i], s[j])
		}
	}
	return result
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
