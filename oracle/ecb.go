package oracle

import (
	"fmt"

	"github.com/saclark/cryptopals-go/aes"
	"github.com/saclark/cryptopals-go/attack"
	"github.com/saclark/cryptopals-go/pkcs7"
)

// NewECBByteAtATimeOracle creates an encryption oracle that will prepend it's
// input to targetPlaintext and then encrypt that using AES in ECB mode under
// the same key upon each invocation. An attacker should be able to recover
// targetPlaintext from this oracle.
func NewECBByteAtATimeOracle(targetPlaintext []byte) (attack.EncryptionOracle, error) {
	key, err := randomBlock(aes.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("generating random key: %w", err)
	}
	oracle := func(input []byte) ([]byte, error) {
		plaintext := make([]byte, len(input))
		copy(plaintext, input)
		plaintext = append(plaintext, targetPlaintext...)
		plaintext = pkcs7.Pad(plaintext, aes.BlockSize)
		return aes.EncryptECB(plaintext, key)
	}
	return oracle, nil
}
