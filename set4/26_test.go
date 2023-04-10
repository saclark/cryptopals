package set4

import (
	"crypto/aes"
	"strings"
	"testing"

	"github.com/saclark/cryptopals/cipher"
	"github.com/saclark/cryptopals/internal/testutil"
)

func TestChallenge26(t *testing.T) {
	oracle := NewCTRBitFlippingOracle()

	encryptedForge := ForgeAdminRoleCTR(oracle.EncryptUserComments)

	decryptedForge, err := cipher.CTRCrypt(encryptedForge, oracle.Key, oracle.IV)
	if err != nil {
		t.Fatalf("decrypting encoded data: %v", err)
	}

	got := string(decryptedForge)
	if want := ";admin=true;"; !strings.Contains(got, want) {
		t.Errorf("wanted '%x' to contain '%x'", got, want)
	}
}

// CTRBitFlippingOracle implements an encryption oracle that takes some input,
// escapes any ";" and "=" characters, injects it into the string:
//
//	comment1=cooking%20MCs;userdata={input};comment2=%20like%20a%20pound%20of%20bacon
//
// and then encrypts that using AES in CTR mode under the same key and IV upon
// each invocation. An attacker should be able to use this oracle to craft a
// ciphertext that decrypts to a plaintext containing ";admin=true;". Attackers
// can use Key and IV to verify their attacks.
type CTRBitFlippingOracle struct {
	Key []byte
	IV  []byte
}

// NewCTRBitFlippingOracle creates a new CTRBitFlippingOracle with a randomly
// generated Key and IV.
func NewCTRBitFlippingOracle() *CTRBitFlippingOracle {
	key := testutil.MustRandomBytes(aes.BlockSize)
	iv := testutil.MustRandomBytes(aes.BlockSize)
	return &CTRBitFlippingOracle{Key: key, IV: iv}
}

// EncryptUserComments acts as the encryption oracle.
func (o *CTRBitFlippingOracle) EncryptUserComments(userData string) []byte {
	userData = strings.ReplaceAll(userData, ";", "%3B")
	userData = strings.ReplaceAll(userData, "=", "%3D")
	plaintext := []byte("comment1=cooking%20MCs;userdata=" + userData + ";comment2=%20like%20a%20pound%20of%20bacon")
	return testutil.Must(cipher.CTRCrypt(plaintext, o.Key, o.IV))
}
