package pkcs7

// Pad pads the plaintext to a multiple of blockSize according to PKCS#7 rules.
// It panics if blockSize is < 1 or > 255.
func Pad(plaintext []byte, blockSize int) []byte {
	if blockSize < 1 || blockSize > 255 {
		panic("pkcs7.Pad: blockSize not in range [1, 255]")
	}

	n := blockSize - len(plaintext)%blockSize
	b := byte(n)
	for i := 0; i < n; i++ {
		plaintext = append(plaintext, b)
	}

	return plaintext
}

// Unpad removes padding from a plaintext that was padded to a multiple of
// blockSize according to PKCS#7 rules. It panics if blockSize is < 1 or > 255.
func Unpad(plaintext []byte, blockSize int) ([]byte, bool) {
	if blockSize < 1 || blockSize > 255 {
		panic("pkcs7.Unpad: blockSize not in range [1, 255]")
	}

	if len(plaintext) == 0 || len(plaintext)%blockSize != 0 {
		return plaintext, false
	}

	i := len(plaintext) - 1
	b := plaintext[i]
	j := len(plaintext) - int(b)

	if b == 0x00 || j < 0 {
		return plaintext, false
	}

	for i -= 1; i >= j; i-- {
		if plaintext[i] != b {
			return plaintext, false
		}
	}

	return plaintext[:j], true
}
