// # Byte-at-a-time ECB decryption (Harder)
//
// Take your oracle function from #12. Now generate a random count of random
// bytes and prepend this string to every plaintext. You are now doing:
//
// 	AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
//
// Same goal: decrypt the target-bytes.
//
// > # Stop and think for a second.
// > What's harder than challenge #12 about doing this? How would you overcome
// > that obstacle? The hint is: you're using all the tools you already have;
// > no crazy math is required.
// >
// > Think "STIMULUS" and "RESPONSE".

package set2

import (
	"fmt"

	"github.com/saclark/cryptopals-go/aes"
	"github.com/saclark/cryptopals-go/attack"
	"github.com/saclark/cryptopals-go/pkcs7"
)

func CrackInputSandwichingECBOracle(maxBlockSize int, oracle func([]byte) ([]byte, error)) ([]byte, error) {
	return attack.CrackECBOracleByteAtATime(maxBlockSize, oracle)
}

// NewInputSandwichingECBOracle creates an encryption oracle that will prepend
// to it's input the same random count of the same random bytes, as well as
// append to it's input targetPlaintext. It will then encrypt that using AES in
// ECB mode under the same key upon each invocation. An attacker should be able
// to recover targetPlaintext from this oracle.
func NewInputSandwichingECBOracle(targetPlaintext []byte) (oracle func([]byte) ([]byte, error), err error) {
	key, err := randomBytes(aes.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("generating random key: %w", err)
	}
	n, err := randomInt(aes.BlockSize * 2)
	if err != nil {
		return nil, fmt.Errorf("generating random count of pre-input bytes: %w", err)
	}
	randPrefix, err := randomBytes(n)
	if err != nil {
		return nil, fmt.Errorf("generating random pre-input bytes: %w", err)
	}

	oracle = func(input []byte) ([]byte, error) {
		var plaintext []byte
		plaintext = append(plaintext, randPrefix...)
		plaintext = append(plaintext, input...)
		plaintext = append(plaintext, targetPlaintext...)
		plaintext = pkcs7.Pad(plaintext, aes.BlockSize)
		return aes.EncryptECB(plaintext, key)
	}

	return oracle, nil
}
