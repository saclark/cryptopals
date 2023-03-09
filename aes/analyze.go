package aes

import (
	"fmt"
)

var ecbProbePlaintext = make([]byte, BlockSize*BlockSize)

func DetectMode(encrypt func(plaintext []byte) ([]byte, error)) (Mode, error) {
	ciphertext, err := encrypt(ecbProbePlaintext)
	if err != nil {
		return 0, fmt.Errorf("calling encrypt: %v", err)
	}
	if DetectECB(ciphertext) >= 0.1 {
		return ModeECB, nil
	}
	return ModeCBC, nil
}

// DetectECB returns a number in the range [0, 1] indicating the fraction of
// ciphertext blocks that are duplicated. A higher score indicates a higher
// likelihood that the ciphertext was encrypted with ECB. It panics if
// ciphertext is not a multiple of BlockSize.
func DetectECB(ciphertext []byte) float64 {
	if len(ciphertext) == 0 {
		return 0
	}

	if len(ciphertext)%BlockSize != 0 {
		panic("aes.DetectECB: ciphertext size not a multiple of block size")
	}

	n := len(ciphertext) / BlockSize
	uniques := make(map[string]struct{}, n)
	for i := 0; i+BlockSize < len(ciphertext); i += BlockSize {
		uniques[string(ciphertext[i:i+BlockSize])] = struct{}{}
	}

	return float64(n-len(uniques)) / float64(n)
}
