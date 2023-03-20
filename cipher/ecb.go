package cipher

import (
	"crypto/cipher"
)

// ECB implements the ECB block cipher mode.
type ECB struct {
	block cipher.Block
}

// NewECB returns a new ECB.
func NewECB(block cipher.Block) *ECB {
	return &ECB{block}
}

// Encrypt encrypts src into dst. Src length must be a multiple of the block
// size and dst must have length >= src.
func (c *ECB) Encrypt(dst, src []byte) {
	c.cryptECB(dst, src, c.block.Encrypt)
}

// Decrypt decrypts src into dst. Src length must be a multiple of the block
// size and dst must have length >= src.
func (c *ECB) Decrypt(dst, src []byte) {
	c.cryptECB(dst, src, c.block.Decrypt)
}

func (c *ECB) cryptECB(dst, src []byte, cryptBlock func(dst, src []byte)) {
	blockSize := c.block.BlockSize()
	if len(src)%blockSize != 0 {
		panic("cryptopals/cipher: input not multiple of block size")
	}
	if len(dst) < len(src) {
		panic("cryptopals/cipher: output smaller than input")
	}
	for i, j := 0, blockSize; j <= len(src); i, j = i+blockSize, j+blockSize {
		cryptBlock(dst[i:j], src[i:j])
	}
}
