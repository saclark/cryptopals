package aes

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/saclark/cryptopals-go/pkcs7"
)

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

type EncryptionOracle struct {
	Mode      Mode
	Key       []byte
	IV        []byte
	JunkByteN int // number of junk bytes to prepend and append to plaintext
}

func NewEncryptionOracle() (*EncryptionOracle, error) {
	oracle := &EncryptionOracle{}

	// Generate a random key.
	oracle.Key = make([]byte, BlockSize)
	if _, err := rand.Read(oracle.Key); err != nil {
		return nil, fmt.Errorf("generating random key: %v", err)
	}

	// Choose count of random junk bytes to prepend and append.
	n, err := rand.Int(rand.Reader, big.NewInt(6))
	if err != nil {
		return nil, fmt.Errorf("choosing random pading value: %v", err)
	}
	oracle.JunkByteN = int(n.Int64() + 5)

	// Choose mode.
	n, err = rand.Int(rand.Reader, big.NewInt(2))
	if err != nil {
		return nil, fmt.Errorf("choosing random encryption mode: %v", err)
	}

	if n.Int64() == 0 {
		oracle.Mode = ModeECB
		return oracle, nil
	}

	// Generate a random IV.
	oracle.IV = make([]byte, BlockSize)
	if _, err := rand.Read(oracle.IV); err != nil {
		return nil, fmt.Errorf("generating random IV: %v", err)
	}

	oracle.Mode = ModeCBC
	return oracle, nil
}

func (o *EncryptionOracle) Encrypt(plaintext []byte) ([]byte, error) {
	pt := o.wrapWithJunk(plaintext)
	pt = pkcs7.Pad(pt, BlockSize)
	if o.Mode == ModeECB {
		return EncryptECB(pt, o.Key)
	}
	return EncryptCBC(pt, o.Key, o.IV)
}

func (o *EncryptionOracle) wrapWithJunk(plaintext []byte) []byte {
	b := byte(o.JunkByteN)
	wrapped := make([]byte, len(plaintext)+o.JunkByteN*2)
	for i := 0; i < o.JunkByteN; i++ {
		wrapped[i], wrapped[len(wrapped)-1-i] = b, b
	}
	copy(wrapped[o.JunkByteN:len(wrapped)-o.JunkByteN], plaintext)
	return wrapped
}

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
