package aes

import (
	"crypto/aes"
	"errors"
)

// The AES block size in bytes.
const BlockSize = aes.BlockSize

var ErrInputNotMultipleOfBlockSize = errors.New("aes: input not multiple of block size")
