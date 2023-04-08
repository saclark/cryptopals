package set2

import (
	"crypto/aes"
	"strings"
	"testing"

	"github.com/saclark/cryptopals/cipher"
	"github.com/saclark/cryptopals/internal/testutil"
	"github.com/saclark/cryptopals/pkcs7"
)

func TestChallenge16(t *testing.T) {
	oracle := NewCBCBitFlippingOracle()

	encryptedForge, err := ForgeAdminRoleCBC(oracle.EncryptUserComments)
	if err != nil {
		t.Fatalf("forging admin user data: %v", err)
	}

	decryptedForge, err := cipher.CBCDecrypt(encryptedForge, oracle.Key, oracle.IV)
	if err != nil {
		t.Fatalf("decrypting encoded data: %v", err)
	}

	got := string(decryptedForge)
	if want := ";admin=true;"; !strings.Contains(got, want) {
		t.Errorf("wanted '%s' to contain '%s'", got, want)
	}
}

// CBCBitFlippingOracle implements an encryption oracle that takes some input,
// escapes any ";" and "=" characters, injects it into the string:
//
//	comment1=cooking%20MCs;userdata={input};comment2=%20like%20a%20pound%20of%20bacon
//
// and then encrypts that using AES in CBC mode under the same key and IV upon
// each invocation. An attacker should be able to use this oracle to craft a
// ciphertext that decrypts to a plaintext containing ";admin=true;". Attackers
// can use Key and IV to verify their attacks.
type CBCBitFlippingOracle struct {
	Key []byte
	IV  []byte
}

// NewCBCBitFlippingOracle creates a new CBCBitFlippingOracle with a randomly
// generated Key and IV.
func NewCBCBitFlippingOracle() *CBCBitFlippingOracle {
	key := testutil.MustRandomBytes(aes.BlockSize)
	iv := testutil.MustRandomBytes(aes.BlockSize)
	return &CBCBitFlippingOracle{Key: key, IV: iv}
}

// EncryptUserComments acts as the encryption oracle.
func (o *CBCBitFlippingOracle) EncryptUserComments(userData string) ([]byte, error) {
	userData = strings.ReplaceAll(userData, ";", "%3B")
	userData = strings.ReplaceAll(userData, "=", "%3D")
	plaintext := []byte("comment1=cooking%20MCs;userdata=" + userData + ";comment2=%20like%20a%20pound%20of%20bacon")
	plaintext = pkcs7.Pad(plaintext, aes.BlockSize)
	return cipher.CBCEncrypt(plaintext, o.Key, o.IV)
}
