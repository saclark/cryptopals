package set2

import (
	"testing"

	"github.com/saclark/cryptopals-go/aes"
	"github.com/saclark/cryptopals-go/pkcs7"
)

// ECB cut-and-paste
// See: https://www.cryptopals.com/sets/2/challenges/13
func TestChallenge13(t *testing.T) {
	oracle, err := NewUserProfileOracle()
	if err != nil {
		t.Fatalf("creating oracle: %v", err)
	}

	encryptedForge, err := ForgeAdminProfile(oracle.CreateEncryptedProfile)
	if err != nil {
		t.Fatalf("forging admin profile: %v", err)
	}

	decryptedForge, err := aes.DecryptECB(encryptedForge, oracle.Key)
	if err != nil {
		t.Fatalf("decrypting encoded profile: %v", err)
	}

	unpaddedForge, ok := pkcs7.Unpad(decryptedForge, aes.BlockSize)
	if !ok {
		t.Fatalf("invalid padding on encoded profile: %s", unpaddedForge)
	}

	forgedProfile, err := DecodeUserProfile(string(unpaddedForge))
	if err != nil {
		t.Fatalf("decoding encoded profile: %v", err)
	}

	if want := "admin"; want != forgedProfile.Role {
		t.Errorf("want: '%s', got: '%s', encoded profile = %s", want, forgedProfile.Role, unpaddedForge)
	}
}
