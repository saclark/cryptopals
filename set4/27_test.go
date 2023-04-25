package set4

import (
	"bytes"
	"crypto/aes"
	"fmt"
	"testing"
	"unicode/utf8"

	"github.com/saclark/cryptopals/cipher"
	"github.com/saclark/cryptopals/internal/testutil"
	"github.com/saclark/cryptopals/pkcs7"
)

func TestChallenge27(t *testing.T) {
	oracle := NewCBCIVIsKeyOracle()

	got, err := RecoverKeyFromCBCIVIsKeyOracle(oracle.Encrypt, oracle.Decrypt)
	if err != nil {
		t.Fatalf("recovering key from IV=Key oracle: %v", err)
	}

	if want := oracle.Key; !bytes.Equal(want, got) {
		t.Fatalf("want: '%x', got: '%x'", want, got)
	}
}

// CBCIVIsKeyOracle implements an encryption/decryption oracle that takes some
// input, encrypts it using AES in CBC mode under the same key upon each
// invocation, using the key as the IV. An attacker should be able to use this
// oracle to recover the key. Attackers can use Key to verify their attacks.
type CBCIVIsKeyOracle struct {
	Key []byte
}

// NewCBCIVIsKeyOracle creates a new CBCIVIsKeyOracle with a randomly generated
// Key.
func NewCBCIVIsKeyOracle() *CBCIVIsKeyOracle {
	key := testutil.MustRandomBytes(aes.BlockSize)
	return &CBCIVIsKeyOracle{Key: key}
}

// Encrypt acts as the encryption oracle, which returns the encrypted plaintext.
func (o *CBCIVIsKeyOracle) Encrypt(plaintext []byte) []byte {
	plaintext = pkcs7.Pad(plaintext, aes.BlockSize)
	return testutil.Must(cipher.CBCEncrypt(plaintext, o.Key, o.Key))
}

// Decrypt acts as the decryption oracle, which decrypts the ciphertext and
// validates the plaintext is ASCII, returning an error containing the plaintext
// if not.
func (o *CBCIVIsKeyOracle) Decrypt(ciphertext []byte) error {
	plaintext, err := cipher.CBCDecrypt(ciphertext, o.Key, o.Key)
	if err != nil {
		return fmt.Errorf("AES-CBC decrypting: %w", err)
	}

	plaintext, err = pkcs7.Unpad(plaintext, aes.BlockSize)
	if err != nil {
		return fmt.Errorf("removing PKCS#7 padding: %w", err)
	}

	for i := 0; i < len(plaintext); i++ {
		if plaintext[i] >= utf8.RuneSelf {
			return fmt.Errorf("not valid ASCII: %s", plaintext)
		}
	}

	return nil
}
