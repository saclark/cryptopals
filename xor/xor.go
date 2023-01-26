package xor

import "math"

// Fixed XORs two byte arrays of equal length. It a panics if the byte arrays
// are not of equal length.
func Fixed(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("arguments must be of the same length")
	}

	result := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		result[i] = a[i] ^ b[i]
	}

	return result
}

// RepeatingByte XORs a byte array with a single repeating byte.
func RepeatingByte(a []byte, b byte) []byte {
	result := make([]byte, len(a))
	for i, x := range a {
		result[i] = x ^ b
	}
	return result
}

// Repeating XORs two byte arrays that may or may not be of equal length.
// If one byte array is shorter, it will be repeated.
func Repeating(a, b []byte) []byte {
	if len(a) == 0 || len(b) == 0 {
		return []byte{}
	}

	l := maxInt(len(a), len(b))
	result := make([]byte, l)
	for i := 0; i < l; i++ {
		result[i] = a[i%len(a)] ^ b[i%len(b)]
	}

	return result
}

// DetectRepeatingByteKey returns a single byte and a score representing the
// most promising (highest scoring) byte that could have been used as a
// reapeating key in an XOR cipher with the given cipher text.
func DetectRepeatingByteKey(ciphertext []byte) (byte, float64) {
	var (
		key   byte
		score float64
	)
	for i := 0; i < 256; i++ {
		k := byte(i)
		plaintext := RepeatingByte(ciphertext, k)
		s := scoreEnglishLikeness(plaintext)
		if s >= score {
			key, score = k, s
		}
	}
	return key, score
}

// DetectRepeatingKey returns a key and a score representing the
// most promising (highest scoring) key that could have been used as a
// reapeating key in an XOR cipher with the given cipher text. It will attempt
// to detect a key no shorter than minKeySize and no longer than maxKeySize. The
// blockComparisons argument specifies the number of consecutive blocks of
// bytes, up to maxKeySize long, from ciphertext that are to be compared when
// detecting the key size. It panics if minKeySize, maxKeySize, or
// blockComparisons is <= 0, if maxKeySize is less than minKeySize, or if
// blockComparisons is >= len(ciphertext)/maxKeySize.
func DetectRepeatingKey(ciphertext []byte, minKeySize, maxKeySize, blockComparisons int) ([]byte, float64) {
	keySize, _ := detectKeySize(ciphertext, minKeySize, maxKeySize, blockComparisons)
	keyByteGroups := transposeBlocks(ciphertext, keySize)

	key := make([]byte, len(keyByteGroups))
	for i, group := range keyByteGroups {
		b, _ := DetectRepeatingByteKey(group)
		key[i] = b
	}

	plaintext := Repeating(ciphertext, key)

	return key, scoreEnglishLikeness(plaintext)
}

func detectKeySize(ciphertext []byte, minKeySize, maxKeySize, blockComparisons int) (int, float64) {
	if minKeySize <= 0 || maxKeySize <= 0 {
		panic("minKeySize and maxKeySize must be greater than 0")
	}
	if maxKeySize < minKeySize {
		panic("maxKeySize must be greater than minKeySize")
	}

	var keySize int
	minScore := math.MaxFloat64
	for k := maxKeySize; k >= minKeySize; k-- {
		score := scoreRepeatingKeySize(ciphertext[:k*(blockComparisons+1)], k)
		if score < minScore {
			keySize, minScore = k, score
		}
	}

	return keySize, minScore
}
