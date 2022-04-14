package xor

import (
	"math"
	"math/bits"
)

// FixedXOR XORs two byte arrays of equal length. It a panics if the byte arrays
// are not of equal length.
func FixedXOR(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("arguments must be of the same length")
	}

	result := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		result[i] = a[i] ^ b[i]
	}

	return result
}

// RepeatingByteXOR XORs a byte array with a single repeating byte.
func RepeatingByteXOR(a []byte, b byte) []byte {
	result := make([]byte, len(a))
	for i, x := range a {
		result[i] = x ^ b
	}
	return result
}

// RepeatingByteXOR XORs two byte arrays that may or may not be of equal length.
// If one byte array is shorter, it will be repeated.
func RepeatingXOR(a, b []byte) []byte {
	if len(a) == 0 || len(b) == 0 {
		return []byte{}
	}

	l := max(len(a), len(b))
	result := make([]byte, l)
	for i := 0; i < l; i++ {
		result[i] = a[i%len(a)] ^ b[i%len(b)]
	}

	return result
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// DetectRepeatingByteXORKey returns a single byte and a score representing the
// most promising (highest scoring) byte that could have been used as a
// reapeating key in an XOR cipher with the given cipher text.
func DetectRepeatingByteXORKey(cipherText []byte) (byte, float64) {
	var key byte
	var score float64
	for i := 0; i < 256; i++ {
		k := byte(i)
		plainText := RepeatingByteXOR(cipherText, k)
		s := englishScore(plainText)
		if s >= score {
			key = k
			score = s
		}
	}
	return key, score
}

func englishScore(s []byte) float64 {
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

// DetectRepeatingByteXORKey returns a key and a score representing the
// most promising (highest scoring) key that could have been used as a
// reapeating key in an XOR cipher with the given cipher text. It will attempt
// to detect a key no shorter than minKeySize and no longer than maxKeySize. The
// blockComparisons argument specifies the number of consecutive blocks of
// bytes, up to maxKeySize long, from cipherText that are to be compared when
// detecting the key size. It panics if minKeySize, maxKeySize, or
// blockComparisons is <= 0, if maxKeySize is less than minKeySize, or if
// blockComparisons is >= len(cipherText)/maxKeySize.
func DetectRepeatingXORKey(cipherText []byte, minKeySize, maxKeySize, blockComparisons int) ([]byte, float64) {
	keySize, _ := detectKeySize(cipherText, minKeySize, maxKeySize, blockComparisons)
	keyGroup := transposeBlocks(cipherText, keySize)

	decodedKey := make([]byte, len(keyGroup))
	for i, group := range keyGroup {
		b, _ := DetectRepeatingByteXORKey(group)
		decodedKey[i] = b
	}

	plainText := RepeatingXOR(cipherText, decodedKey)

	return decodedKey, englishScore(plainText)
}

func detectKeySize(cipherText []byte, minKeySize, maxKeySize, blockComparisons int) (int, float64) {
	if minKeySize <= 0 || maxKeySize <= 0 {
		panic("minKeySize and maxKeySize must be greater than 0")
	}
	if maxKeySize < minKeySize {
		panic("maxKeySize must be greater than minKeySize")
	}

	var keySize int
	minScore := math.MaxFloat64
	for k := maxKeySize; k >= minKeySize; k-- {
		score := scoreKeySize(cipherText, k, blockComparisons)
		if score < minScore {
			keySize = k
			minScore = score
		}
	}

	return keySize, minScore
}

func scoreKeySize(cipherText []byte, keySize, blockComparisons int) float64 {
	if blockComparisons <= 0 {
		panic("blockComparisons must be greater than 0")
	}
	if blockComparisons >= len(cipherText)/keySize {
		panic("blockComparisons must be less than len(cipherText)/keySize")
	}

	var dist int
	for i := 0; i < blockComparisons; i++ {
		low, mid, high := keySize*i, keySize*(i+1), keySize*(i+2)
		dist += hammingDistance(cipherText[low:mid], cipherText[mid:high])
	}

	return (float64(dist) / float64(blockComparisons)) / float64(keySize)
}

func hammingDistance(a, b []byte) int {
	var dist int
	for i := 0; i < len(a) || i < len(b); i++ {
		if i < len(a) && i < len(b) {
			dist += bits.OnesCount8(a[i] ^ b[i])
		} else {
			dist += 8
		}
	}
	return dist
}

func transposeBlocks(s []byte, blockSize int) [][]byte {
	if blockSize <= 0 {
		panic("n must be greater than 0")
	}
	result := make([][]byte, min(len(s), blockSize))
	for i := 0; i < blockSize; i++ {
		for j := i; j < len(s); j += blockSize {
			result[i] = append(result[i], s[j])
		}
	}
	return result
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
