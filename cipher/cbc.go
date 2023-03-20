package cipher

import (
	"crypto/cipher"

	"github.com/saclark/cryptopals-go/xor"
)

// CBC implements the CBC block cipher mode. The Go standard library already
// provides a proper implementation of this. This was written as a learning
// exercise.
type CBC struct {
	block cipher.Block
	iv    []byte
}

// NewCBC returns a new CBC that uses the given block cipher and IV for all
// calls to Encrypt and Decrypt. The IV must have length equal to the block
// size.
func NewCBC(block cipher.Block, iv []byte) *CBC {
	if len(iv) != block.BlockSize() {
		panic("cryptopals/cipher: IV size not block size")
	}
	return &CBC{block: block, iv: iv}
}

// Encrypt encrypts src into dst. Src length must be a multiple of the block
// size and dst must have length >= src.
func (c *CBC) Encrypt(dst, src []byte) {
	c.cryptCBC(dst, src, func(dst, tmpDst, src, prev []byte) []byte {
		xor.BytesFixed(tmpDst, src, prev)
		c.block.Encrypt(dst, tmpDst)
		return dst
	})
}

// Decrypt decrypts src into dst. Src length must be a multiple of the block
// size and dst must have length >= src.
func (c *CBC) Decrypt(dst, src []byte) {
	c.cryptCBC(dst, src, func(dst, tmpDst, src, prev []byte) []byte {
		c.block.Decrypt(tmpDst, src)
		xor.BytesFixed(dst, tmpDst, prev)
		return src
	})
}

func (c *CBC) cryptCBC(dst, src []byte, cryptBlock func(dst, tmpDst, src, prev []byte) []byte) {
	blockSize := c.block.BlockSize()
	if len(src)%blockSize != 0 {
		panic("cryptopals/cipher: input not multiple of block size")
	}
	if len(dst) < len(src) {
		panic("cryptopals/cipher: output smaller than input")
	}
	tmpDst := make([]byte, blockSize)
	prev := c.iv
	for i, j := 0, blockSize; j <= len(src); i, j = i+blockSize, j+blockSize {
		prev = cryptBlock(dst[i:j], tmpDst, src[i:j], prev)
	}
}
