package xor

import "math/bits"

// scoreEnglishLikeness scores the likelihood that s represents english text.
// The higher the score the more likely.
func scoreEnglishLikeness(s []byte) float64 {
	var score float64
	for _, b := range s {
		switch {
		case (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z'):
			score++
		case b == ' ':
			score += 3
		}
	}
	return score
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

	return (float64(dist) / float64(n)) / float64(keySize)
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
