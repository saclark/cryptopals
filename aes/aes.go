package aes

import (
	"crypto/aes"
	"errors"
)

// The AES block size in bytes.
const BlockSize = aes.BlockSize

var ErrInputNotMultipleOfBlockSize = errors.New("aes: input not multiple of block size")

type Mode int

func (m Mode) String() string {
	switch m {
	case ModeECB:
		return "ECB"
	case ModeCBC:
		return "CBC"
	default:
		panic("aes: invalid Mode")
	}
}

const (
	ModeECB Mode = iota
	ModeCBC
)
