package set2

import (
	"crypto/aes"
	"testing"

	"github.com/saclark/cryptopals-go/cipher"
	"github.com/saclark/cryptopals-go/pkcs7"
)

// ECB cut-and-paste
// See: https://www.cryptopals.com/sets/2/challenges/13
func TestChallenge13(t *testing.T) {
	oracle, err := NewECBCutAndPasteOracle()
	if err != nil {
		t.Fatalf("creating oracle: %v", err)
	}

	encryptedForge, err := ForgeAdminRoleECB(oracle.CreateEncryptedProfile)
	if err != nil {
		t.Fatalf("forging admin profile: %v", err)
	}

	decryptedForge, err := cipher.ECBDecrypt(encryptedForge, oracle.Key)
	if err != nil {
		t.Fatalf("decrypting encoded profile: %v", err)
	}

	unpaddedForge, err := pkcs7.Unpad(decryptedForge, aes.BlockSize)
	if err != nil {
		t.Fatalf("unpadding encoded profile '%x': %v", unpaddedForge, err)
	}

	forgedProfile, err := DecodeUserProfile(string(unpaddedForge))
	if err != nil {
		t.Fatalf("decoding encoded profile: %v", err)
	}

	if want := "admin"; want != forgedProfile.Role {
		t.Errorf("want: '%s', got: '%s', encoded profile = %s", want, forgedProfile.Role, unpaddedForge)
	}
}
