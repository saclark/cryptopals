package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"

	"github.com/saclark/cryptopals-go/xor"
)

// CryptCTR encrypts/decrypts the input using AES-CTR. The Go standard library
// already provides a proper implementation of this, but we're implementing it
// here ourselves (poorly) in order to better understand it.
func CryptCTR(input, key []byte, nonce uint64) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}
	ks, err := newCTRKeyStream(block, nonce)
	if err != nil {
		return nil, fmt.Errorf("creating keystream: %w", err)
	}

	ksb := make([]byte, BlockSize)
	output := make([]byte, len(input))
	for i := 0; i < len(input); i += BlockSize {
		j := minInt(i+BlockSize, len(input))
		if err := ks.readBlock(ksb); err != nil {
			return nil, fmt.Errorf("generating next keystream block: %w", err)
		}
		xor.BytesFixed(output[i:j], ksb[:j-i], input[i:j])
	}

	return output, nil
}

func minInt(x, y int) int {
	if x < y {
		return x
	}
	return y
}

type ctrKeyStream struct {
	block cipher.Block
	ctr   uint64
	src   writeableBytes
}

func newCTRKeyStream(block cipher.Block, nonce uint64) (*ctrKeyStream, error) {
	if block.BlockSize() != BlockSize {
		panic("cryptopals/aes: cipher block size not 16")
	}
	ks := &ctrKeyStream{
		block: block,
		src:   writeableBytes(make([]byte, BlockSize)),
	}
	if err := binary.Write(ks.src[:8], binary.LittleEndian, nonce); err != nil {
		return nil, fmt.Errorf("writing nonce: %w", err)
	}
	return ks, nil
}

func (k *ctrKeyStream) readBlock(dst []byte) error {
	if err := binary.Write(k.src[8:], binary.LittleEndian, k.ctr); err != nil {
		return fmt.Errorf("writing block number: %w", err)
	}
	k.block.Encrypt(dst, k.src)
	k.ctr++
	return nil
}

type writeableBytes []byte

func (b writeableBytes) Write(p []byte) (n int, err error) {
	n = copy(b, p)
	return n, nil
}
