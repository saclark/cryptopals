// # An ECB/CBC detection oracle
//
// Now that you have ECB and CBC working:
//
// Write a function to generate a random AES key; that's just 16 random bytes.
//
// Write a function that encrypts data under an unknown key --- that is, a
// function that generates a random key and encrypts under it.
//
// The function should look like:
//
// 	encryption_oracle(your-input)
// 	=> [MEANINGLESS JIBBER JABBER]
//
// Under the hood, have the function _append_ 5-10 bytes (count chosen randomly)
// _before_ the plaintext and 5-10 bytes _after_ the plaintext.
//
// Now, have the function choose to encrypt under ECB 1/2 the time, and under
// CBC the other half (just use random IVs each time for CBC). Use rand(2) to
// decide which to use.
//
// Detect the block cipher mode the function is using each time. You should end
// up with a piece of code that, pointed at a block box that might be encrypting
// ECB or CBC, tells you which one is happening.

package set2

import (
	"crypto/aes"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/saclark/cryptopals-go/attack"
	"github.com/saclark/cryptopals-go/cipher"
	"github.com/saclark/cryptopals-go/pkcs7"
)

func DetectECBModeOracle(oracle func([]byte) ([]byte, error)) (isECB bool, err error) {
	return attack.IsOracleECBMode(aes.BlockSize, oracle)
}

// ModeDetectionOracle implements an encryption oracle that will add 5-10 bytes
// to both the beginning and end of it's input and then encrypt that using AES
// with a different random mode, key, and IV (if CBC mode), upon each call to
// Encrypt. IsECB is updated upon each call to Encrypt, indicating
// whether ECB mode was used.
type ModeDetectionOracle struct {
	IsECB bool
}

// Encrypt is an encryption oracle that adds 5-10 bytes to both the beginning
// and end of the input and then encrypts that using AES with a different
// random mode, key, and IV (if CBC mode), upon each invocation.
func (o *ModeDetectionOracle) Encrypt(input []byte) (ciphertext []byte, err error) {
	o.IsECB, err = randomBool()
	if err != nil {
		return nil, fmt.Errorf("choosing random mode: %w", err)
	}
	key, err := randomBytes(aes.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("generating random key: %w", err)
	}
	plaintext, err := junkifyAndPad(input)
	if err != nil {
		return nil, fmt.Errorf("junkifying and padding input: %w", err)
	}
	if o.IsECB {
		return cipher.ECBEncrypt(plaintext, key)
	}
	iv, err := randomBytes(aes.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("generating random IV: %v", err)
	}
	return cipher.CBCEncrypt(plaintext, key, iv)
}

func junkifyAndPad(input []byte) ([]byte, error) {
	n, err := randomInt(6)
	if err != nil {
		return nil, fmt.Errorf("generating random int in range [0,6): %v", err)
	}
	n = n + 5

	junkified := make([]byte, len(input)+n*2)
	if _, err := rand.Read(junkified[:n]); err != nil {
		return nil, fmt.Errorf("reading %d random bytes: %v", n, err)
	}

	copy(junkified[n:len(junkified)-n], input)

	if _, err := rand.Read(junkified[len(junkified)-n:]); err != nil {
		return nil, fmt.Errorf("reading %d random bytes: %v", n, err)
	}

	return pkcs7.Pad(junkified, aes.BlockSize), nil
}

func randomBool() (bool, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(2))
	if err != nil {
		return false, fmt.Errorf("generating random int in range [0, 2): %v", err)
	}
	return n.Int64() == 1, nil
}
