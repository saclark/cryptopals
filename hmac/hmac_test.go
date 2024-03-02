package hmac

import (
	"bytes"
	stdhmac "crypto/hmac"
	"crypto/sha256"
	"fmt"
	"testing"
)

type sha256Hash struct{}

func (sha256Hash) Size() int {
	return sha256.Size
}

func (sha256Hash) BlockSize() int {
	return sha256.BlockSize
}

func (sha256Hash) Sum(message []byte) []byte {
	h := sha256.New()
	h.Write(message)
	return h.Sum(nil)
}

func TestSum(t *testing.T) {
	bs := sha256.New().BlockSize()
	for i := 0; i < bs*2; i++ {
		t.Run(fmt.Sprintf("%d byte key", i), func(t *testing.T) {
			key := bytes.Repeat([]byte{'A'}, i)
			message := []byte("The quick brown fox jumps over the lazy dog.")

			stdHMAC := stdhmac.New(sha256.New, key)
			stdHMAC.Write(message)
			want := stdHMAC.Sum(nil)

			thisHMAC := New(sha256Hash{}, key)
			got := thisHMAC.Sum(message)

			if !bytes.Equal(want, got) {
				t.Fatalf("[%d]: want: '%x', got: '%x'", i, want, got)
			}
		})
	}
}
