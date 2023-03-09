package attack

import "fmt"

type Mode int

func (m Mode) String() string {
	switch m {
	case ModeECB:
		return "ECB"
	case ModeCBC:
		return "CBC"
	default:
		panic("aes: invalid Mode")
	}
}

const (
	ModeECB Mode = iota
	ModeCBC
)

func DetectMode(blockSize int, encrypt EncryptionOracle) (Mode, error) {
	ecbProbePlaintext := make([]byte, blockSize*blockSize)
	ciphertext, err := encrypt(ecbProbePlaintext)
	if err != nil {
		return 0, fmt.Errorf("calling encrypt: %v", err)
	}
	if DetectECBMode(ciphertext, blockSize) >= 0.1 {
		return ModeECB, nil
	}
	return ModeCBC, nil
}

// DetectECBMode returns a number in the range [0, 1] indicating the fraction of
// ciphertext blocks that are duplicated. A higher score indicates a higher
// likelihood that the ciphertext was encrypted with ECB. It panics if
// ciphertext is not a multiple of BlockSize.
func DetectECBMode(ciphertext []byte, blockSize int) float64 {
	if len(ciphertext) == 0 {
		return 0
	}

	if len(ciphertext)%blockSize != 0 {
		panic("aes.DetectECB: ciphertext size not a multiple of block size")
	}

	n := len(ciphertext) / blockSize
	uniques := make(map[string]struct{}, n)
	for i := 0; i+blockSize < len(ciphertext); i += blockSize {
		uniques[string(ciphertext[i:i+blockSize])] = struct{}{}
	}

	return float64(n-len(uniques)) / float64(n)
}
