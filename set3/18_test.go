package set3

import (
	"bytes"
	"testing"
)

func TestChallenge18(t *testing.T) {
	wantCiphertext := base64MustDecodeString("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
	wantPlaintext := []byte("Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ")
	key := []byte("YELLOW SUBMARINE")
	nonce := make([]byte, 8)

	gotPlaintext, err := CryptAESCTR(wantCiphertext, key, nonce)
	if err != nil {
		t.Fatalf("AES-CTR decrypting ciphertext: %v", err)
	}

	if !bytes.Equal(wantPlaintext, gotPlaintext) {
		t.Fatalf("want: '%s', got: '%s'", wantPlaintext, gotPlaintext)
	}

	gotCiphertext, err := CryptAESCTR(gotPlaintext, key, nonce)
	if err != nil {
		t.Fatalf("AES-CTR encrypting plaintext: %v", err)
	}

	if !bytes.Equal(wantCiphertext, gotCiphertext) {
		t.Fatalf("want: '%s', got: '%s'", wantCiphertext, gotCiphertext)
	}
}
