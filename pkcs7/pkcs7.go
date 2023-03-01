package pkcs7

func Pad(plaintext []byte, blockSize int) []byte {
	if blockSize < 1 || blockSize > 255 {
		panic("pkcs7.Pad: blockSize not in range [1, 255]")
	}

	n := blockSize - len(plaintext)%blockSize
	for i := 0; i < n; i++ {
		plaintext = append(plaintext, byte(n))
	}

	return plaintext
}

func Unpad(plaintext []byte) ([]byte, bool) {
	if len(plaintext) == 0 {
		return plaintext, true
	}

	n := int(plaintext[len(plaintext)-1])
	i := len(plaintext) - n
	if n == 0 || i < 0 || i >= len(plaintext) {
		return plaintext, false
	}

	return plaintext[:i], true
}
