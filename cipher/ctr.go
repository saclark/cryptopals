package cipher

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"

	"github.com/saclark/cryptopals-go/xor"
)

const ctrByteSize = 8

// CTR implements the CTR block cipher mode. The Go standard library already
// provides a proper implementation of this. This was written as a learning
// exercise.
type CTR struct {
	block cipher.Block
	nonce []byte
}

// NewCTR returns a new CTR that uses the given block cipher and nonce for all
// calls to Crypt. The nonce must be 8 bytes short of the block size so that it
// fills a full block when combined with a 64-bit unsigned integer block
// counter.
func NewCTR(block cipher.Block, nonce []byte) *CTR {
	if block.BlockSize()-len(nonce) != ctrByteSize {
		panic("cryptopals/cipher: nonce not 8 bytes short of block size")
	}
	return &CTR{block: block, nonce: nonce}
}

// Crypt encrypts/decrypts (these are the same operation in CTR) src into dst.
// Dst must have length >= src.
func (c *CTR) Crypt(dst, src []byte) error {
	if len(dst) < len(src) {
		panic("cryptopals/cipher: output smaller than input")
	}

	blockSize := c.block.BlockSize()

	ksSrc := writeableBytes(make([]byte, blockSize))
	if err := binary.Write(ksSrc[:ctrByteSize], binary.LittleEndian, c.nonce); err != nil {
		return fmt.Errorf("writing nonce: %w", err)
	}

	ksDst := make([]byte, blockSize)
	for i, ctr := 0, uint64(0); i < len(src); i, ctr = i+blockSize, ctr+1 {
		j := minInt(i+blockSize, len(src))
		if err := binary.Write(ksSrc[ctrByteSize:], binary.LittleEndian, ctr); err != nil {
			return fmt.Errorf("writing block counter: %w", err)
		}
		c.block.Encrypt(ksDst, ksSrc)
		xor.BytesFixed(dst[i:j], ksDst[:j-i], src[i:j])
	}

	return nil
}

func minInt(x, y int) int {
	if x < y {
		return x
	}
	return y
}

type writeableBytes []byte

func (b writeableBytes) Write(p []byte) (n int, err error) {
	n = copy(b, p)
	return n, nil
}
