package set2

import (
	"strings"
	"testing"

	"github.com/saclark/cryptopals-go/cipher"
)

func TestChallenge16(t *testing.T) {
	oracle, err := NewCBCBitFlippingOracle()
	if err != nil {
		t.Fatalf("creating oracle: %v", err)
	}

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
