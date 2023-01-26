package xor

import "math/bits"

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

func scoreRepeatingKeySize(ciphertext []byte, keySize int) float64 {
	if keySize <= 0 {
		panic("keysize not greater than 0")
	}
	if len(ciphertext) <= keySize || len(ciphertext)%keySize != 0 {
		panic("ciphertext size not a multiple of key size larger than key size")
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
		panic("a and b are not the same length")
	}
	var dist int
	for i := 0; i < len(a); i++ {
		dist += bits.OnesCount8(a[i] ^ b[i])
	}
	return dist
}

func transposeBlocks(s []byte, blockSize int) [][]byte {
	if blockSize <= 0 {
		panic("blockSize not greater than 0")
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
