package xor

import "math"

// BytesFixed XORs two byte arrays of equal length. It panics if the byte arrays
// are not of equal length.
func BytesFixed(x, y []byte) []byte {
	if len(x) != len(y) {
		panic("xor.Fixed: x and y not same length")
	}

	result := make([]byte, len(x))
	for i := 0; i < len(x); i++ {
		result[i] = x[i] ^ y[i]
	}

	return result
}

// BytesRepeatingByte XORs a byte slice with a single repeating byte.
func BytesRepeatingByte(s []byte, b byte) []byte {
	result := make([]byte, len(s))
	for i, x := range s {
		result[i] = x ^ b
	}
	return result
}

// BytesRepeating XORs two byte arrays that may or may not be of equal length.
// If one byte slice is longer, it will be XORed with the bytes from the shorter
// slice, repeated as necessary.
func BytesRepeating(x, y []byte) []byte {
	if len(x) == 0 || len(y) == 0 {
		return []byte{}
	}

	l := maxInt(len(x), len(y))
	result := make([]byte, l)
	for i := 0; i < l; i++ {
		result[i] = x[i%len(x)] ^ y[i%len(y)]
	}

	return result
}

// DetectRepeatingByteKey returns a single byte and a score representing the
// most promising (highest scoring) byte that could have been used as a
// reapeating key in an XOR cipher with the given ciphertext.
func DetectRepeatingByteKey(ciphertext []byte) (key byte, score float64) {
	for i := 0; i < 256; i++ {
		k := byte(i)
		plaintext := BytesRepeatingByte(ciphertext, k)
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
// to detect a key no shorter than minKeySize and no longer than maxKeySize. It
// panics if minKeySize, maxKeySize, or blockComparisons is <= 0,
// if maxKeySize is < minKeySize, or if maxKeySize is >= len(ciphertext)/2.
func DetectRepeatingKey(ciphertext []byte, minKeySize, maxKeySize int) (key []byte, score float64) {
	keySize := detectRepeatingKeySize(ciphertext, minKeySize, maxKeySize)
	keyByteGroups := transposeBlocks(ciphertext, keySize)

	key = make([]byte, len(keyByteGroups))
	for i, group := range keyByteGroups {
		b, _ := DetectRepeatingByteKey(group)
		key[i] = b
	}

	plaintext := BytesRepeating(ciphertext, key)

	return key, scoreEnglishLikeness(plaintext)
}

// detectRepeatingKeySize detects the most likely key size, in bytes, that
// could have been used to produce the ciphertext from a cipher using a
// repeating-key XOR.
func detectRepeatingKeySize(ciphertext []byte, minKeySize, maxKeySize int) int {
	if minKeySize <= 0 {
		panic("xor.detectKeySize: minKeySize not > 0")
	}
	if maxKeySize <= 0 {
		panic("xor.detectKeySize: maxKeySize not > 0")
	}
	if maxKeySize < minKeySize {
		panic("xor.detectKeySize: maxKeySize not >= minKeySize")
	}
	if maxKeySize > len(ciphertext)/2 {
		panic("xor.detectKeySize: maxKeySize not <= len(ciphertext)/2")
	}

	var keySize int
	minScore := math.MaxFloat64
	for k := maxKeySize; k >= minKeySize; k-- {
		n := len(ciphertext) - len(ciphertext)%k
		score := scoreRepeatingKeySize(ciphertext[:n], k)
		if score < minScore {
			keySize, minScore = k, score
		}
	}

	return keySize
}
