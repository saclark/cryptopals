package cipher

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"github.com/saclark/cryptopals/xor"
)

// CTR implements the CTR block cipher mode. The Go standard library already
// provides a proper implementation of this. This was written as a learning
// exercise.
type CTR struct {
	block cipher.Block
	ctr   []byte
}

// NewCTR returns a new CTR. IV size must equal the block size and the block
// size must be > 8. The last 8 bytes of the IV are incremented to serve as the
// block counter and all prior bytes serve as the nonce.
func NewCTR(block cipher.Block, iv []byte) *CTR {
	if block.BlockSize() <= 8 {
		panic("cryptopals/cipher: block size must be > 8")
	}
	if block.BlockSize() != len(iv) {
		panic("cryptopals/cipher: IV size not block size")
	}
	return &CTR{block: block, ctr: bytes.Clone(iv)}
}

// Crypt encrypts/decrypts (these are the same operation in CTR) src into dst.
// Dst must have length >= src.
func (c *CTR) Crypt(dst, src []byte) {
	if len(dst) < len(src) {
		panic("cryptopals/cipher: output smaller than input")
	}
	bs := c.block.BlockSize()
	ksDst := make([]byte, bs)
	for i := 0; i < len(src); i += bs {
		j := minInt(i+bs, len(src))
		c.block.Encrypt(ksDst, c.ctr)
		xor.BytesFixed(dst[i:j], ksDst[:j-i], src[i:j])

		// Increment last 8 bytes of counter
		for i := 8; i < len(c.ctr); i++ {
			c.ctr[i]++
			if c.ctr[i] != 0 {
				break
			}
		}
	}
}

func minInt(x, y int) int {
	if x < y {
		return x
	}
	return y
}

func CTRCrypt(input, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}
	cbc := NewCTR(block, iv)
	output := make([]byte, len(input))
	cbc.Crypt(output, input)
	return output, nil
}
