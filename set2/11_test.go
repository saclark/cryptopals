package set2

import (
	"crypto/aes"
	"testing"

	"github.com/saclark/cryptopals-go/cipher"
	"github.com/saclark/cryptopals-go/internal/testutil"
	"github.com/saclark/cryptopals-go/pkcs7"
)

// An ECB/CBC detection oracle
// See: https://www.cryptopals.com/sets/2/challenges/11
func TestChallenge11(t *testing.T) {
	var oracle ModeDetectionOracle
	for i := 0; i < 10; i++ {
		got, err := DetectECBModeOracle(oracle.Encrypt)
		if err != nil {
			t.Fatalf("err: %v", err)
		}

		want := oracle.IsECB
		if want != got {
			t.Fatalf("want: '%v', got: '%v'", want, got)
		}
	}
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
	o.IsECB = testutil.MustRandomBool()
	key := testutil.MustRandomBytes(aes.BlockSize)
	plaintext := junkifyAndPad(input)
	if o.IsECB {
		return cipher.ECBEncrypt(plaintext, key)
	}
	iv := testutil.MustRandomBytes(aes.BlockSize)
	return cipher.CBCEncrypt(plaintext, key, iv)
}

func junkifyAndPad(input []byte) []byte {
	n := testutil.MustRandomInt(6) + 5

	junkified := make([]byte, len(input)+n*2)
	testutil.MustReadRandomBytes(junkified[:n])
	copy(junkified[n:len(junkified)-n], input)
	testutil.MustReadRandomBytes(junkified[len(junkified)-n:])

	return pkcs7.Pad(junkified, aes.BlockSize)
}
