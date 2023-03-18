package pkcs7

import "errors"

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

var ErrInvalidPadding = errors.New("invalid padding")

// Unpad removes padding from a plaintext that was padded to a multiple of
// blockSize according to PKCS#7 rules. It panics if blockSize is < 1 or > 255.
// It returns ErrInvalidPadding if the padding is invalid but callers should
// avoid bubbling this error up to their callers, so as to avoid padding oracle
// attacks. Note, however, that this function makes no attempt to keep it's
// execution time consistent between inputs with valid and invalid padding, thus
// still potentially leaking information about padding validity.
func Unpad(plaintext []byte, blockSize int) ([]byte, error) {
	if blockSize < 1 || blockSize > 255 {
		panic("pkcs7.Unpad: blockSize not in range [1, 255]")
	}

	if len(plaintext) == 0 || len(plaintext)%blockSize != 0 {
		return nil, ErrInvalidPadding
	}

	i := len(plaintext) - 1
	b := plaintext[i]
	j := len(plaintext) - int(b)

	if b == 0x00 || j < 0 {
		return nil, ErrInvalidPadding
	}

	for i -= 1; i >= j; i-- {
		if plaintext[i] != b {
			return nil, ErrInvalidPadding
		}
	}

	return plaintext[:j], nil
}
