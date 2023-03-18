package set3

import (
	"bytes"
	"testing"

	"github.com/saclark/cryptopals-go/aes"
	"github.com/saclark/cryptopals-go/pkcs7"
)

func TestChallenge17(t *testing.T) {
	for i := 0; i < 10; i++ {
		oracle, err := NewCBCPaddingOracle()
		if err != nil {
			t.Fatalf("creating CBC padding oracle: %v", err)
		}
		token, iv, err := oracle.GetEncryptedSessionToken()
		if err != nil {
			t.Fatalf("getting encrypted session token: %v", err)
		}
		want, err := aes.DecryptCBC(token, oracle.Key, iv)
		if err != nil {
			t.Fatalf("decrypting session token: %v", err)
		}
		want, err = pkcs7.Unpad(want, aes.BlockSize)
		if err != nil {
			t.Fatalf("unpadding decrypted session token: %v", err)
		}

		got, err := CrackCBCPaddingOracle(token, iv, aes.BlockSize, oracle.HandleEncryptedSessionToken)
		if err != nil {
			t.Fatalf("cracking CBC padding oracle: %v", err)
		}

		if !bytes.Equal(want, got) {
			t.Errorf("want: '%x', got: '%x'", want, got)
		}
	}
}
