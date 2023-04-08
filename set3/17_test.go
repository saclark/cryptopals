package set3

import (
	"bytes"
	"crypto/aes"
	"fmt"
	"testing"

	"github.com/saclark/cryptopals/cipher"
	"github.com/saclark/cryptopals/internal/testutil"
	"github.com/saclark/cryptopals/pkcs7"
)

func TestChallenge17(t *testing.T) {
	for i := 0; i < 10; i++ {
		oracle := NewCBCPaddingOracle()
		token, iv := oracle.GetEncryptedSessionToken()
		want := testutil.Must(cipher.CBCDecrypt(token, oracle.Key, iv))
		want = testutil.Must(pkcs7.Unpad(want, aes.BlockSize))

		got, err := CrackCBCPaddingOracle(token, iv, aes.BlockSize, oracle.HandleEncryptedSessionToken)
		if err != nil {
			t.Fatalf("cracking CBC padding oracle: %v", err)
		}

		if !bytes.Equal(want, got) {
			t.Errorf("want: '%x', got: '%x'", want, got)
		}
	}
}

var challenge17EncodedTokens = []string{
	"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
	"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
	"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
	"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
	"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
	"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
	"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
	"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
	"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
	"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
}

type CBCPaddingOracle struct {
	Key []byte
}

func NewCBCPaddingOracle() *CBCPaddingOracle {
	key := testutil.MustRandomBytes(aes.BlockSize)
	return &CBCPaddingOracle{Key: key}
}

func (o *CBCPaddingOracle) GetEncryptedSessionToken() (encryptedToken, iv []byte) {
	iv = testutil.MustRandomBytes(aes.BlockSize)
	i := testutil.MustRandomInt(len(challenge17EncodedTokens))
	plaintext := testutil.MustBase64DecodeString(challenge17EncodedTokens[i])
	plaintext = pkcs7.Pad(plaintext, aes.BlockSize)
	ciphertext := testutil.Must(cipher.CBCEncrypt(plaintext, o.Key, iv))
	return ciphertext, iv
}

// HandleEncryptedSessionToken acts as the padding oracle. It returns
// an error if the padding of the decrypted token is invalid. Otherwise, it
// returns nil. It simply panics if the token is unable to be decrypted, so
// callers (i.e. attackers) don't have to bother checking the error type.
func (o *CBCPaddingOracle) HandleEncryptedSessionToken(encryptedToken, iv []byte) error {
	plaintext := testutil.Must(cipher.CBCDecrypt(encryptedToken, o.Key, iv))
	_, err := pkcs7.Unpad(plaintext, aes.BlockSize)
	if err != nil {
		return fmt.Errorf("removing PKCS#7 padding: %w", err)
	}
	return nil
}
