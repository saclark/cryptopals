package oracle

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/saclark/cryptopals-go/aes"
	"github.com/saclark/cryptopals-go/attack"
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

// NewModeDetectionOracle creates an encryption oracle that will add 5-10 bytes
// to both the beginning and end of it's input and then encrypt that using AES
// with a different random mode, key, and IV (if CBC mode), upon each
// invocation. An attacker should be able to reliably determine the mode used
// upon each invocation of the encryption oracle so a Mode variable that is set
// to the Mode used by the most recent invocation of the encryption oracle is
// also returned so that attackers can verify their results.
func NewModeDetectionOracle() (attack.EncryptionOracle, Mode, error) {
	var mode Mode
	oracle := func(input []byte) ([]byte, error) {
		var err error
		mode, err = randomMode()
		if err != nil {
			return nil, fmt.Errorf("choosing random mode: %w", err)
		}
		key, err := randomBlock(aes.BlockSize)
		if err != nil {
			return nil, fmt.Errorf("generating random key: %w", err)
		}
		plaintext, err := junkifyAndPad(input)
		if err != nil {
			return nil, fmt.Errorf("junkifying and padding input: %w", err)
		}
		if mode == ModeECB {
			return aes.EncryptECB(plaintext, key)
		}
		iv, err := randomBlock(aes.BlockSize)
		if err != nil {
			return nil, fmt.Errorf("generating random IV: %v", err)
		}
		return aes.EncryptCBC(plaintext, key, iv)
	}
	return oracle, mode, nil
}

func junkifyAndPad(input []byte) ([]byte, error) {
	randInt, err := rand.Int(rand.Reader, big.NewInt(6))
	if err != nil {
		return nil, fmt.Errorf("generating random int in range [0,6): %v", err)
	}

	n := int(randInt.Int64() + 5)
	b := byte(n)

	junkified := make([]byte, len(input)+n*2)
	copy(junkified[n:len(junkified)-n], input)

	for i := 0; i < n; i++ {
		junkified[i], junkified[len(junkified)-1-i] = b, b
	}

	return pkcs7.Pad(junkified, aes.BlockSize), nil
}
