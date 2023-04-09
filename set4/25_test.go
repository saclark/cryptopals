package set4

import (
	"bytes"
	"crypto/aes"
	stdcipher "crypto/cipher"
	"testing"

	"github.com/saclark/cryptopals/cipher"
	"github.com/saclark/cryptopals/internal/testutil"
)

func TestChallenge25(t *testing.T) {
	want := testutil.MustBase64DecodeFile("data/25.txt")
	oracle := NewRandomAccessReadWriteAESCTROracle(want)

	got := CrackRandomAccessReadWriteAESCTR(oracle.Ciphertext, oracle.Edit)

	if !bytes.Equal(want, got) {
		t.Fatalf("want: '%x', got: '%x'", want, got)
	}
}

type RandomAccessReadWriteAESCTROracle struct {
	Ciphertext []byte
	block      stdcipher.Block
	iv         []byte
}

func NewRandomAccessReadWriteAESCTROracle(plaintext []byte) *RandomAccessReadWriteAESCTROracle {
	key := testutil.MustRandomBytes(aes.BlockSize)
	block := testutil.Must(aes.NewCipher(key))

	ciphertext := make([]byte, len(plaintext))
	iv := testutil.MustRandomBytes(block.BlockSize())
	ctr := cipher.NewCTR(block, iv)
	ctr.Crypt(ciphertext, plaintext)

	return &RandomAccessReadWriteAESCTROracle{
		Ciphertext: ciphertext,
		block:      block,
		iv:         iv,
	}
}

func (o *RandomAccessReadWriteAESCTROracle) Edit(offset int, newPlaintext []byte) (newCiphertext []byte) {
	i, j, l := offset, offset+len(newPlaintext), len(o.Ciphertext)
	if l < j {
		l = j
	}

	plaintext := make([]byte, l)
	ctr := cipher.NewCTR(o.block, o.iv)
	ctr.Crypt(plaintext, o.Ciphertext)

	copy(plaintext[i:j], newPlaintext)

	o.Ciphertext = make([]byte, l)
	ctr = cipher.NewCTR(o.block, o.iv)
	ctr.Crypt(o.Ciphertext, plaintext)

	return o.Ciphertext
}
