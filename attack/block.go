package attack

import (
	"errors"
	"fmt"
)

var ErrUnableToDetectBlockSize = errors.New("attack: unable to detect block size")

func DetectBlockSize(maxBlockSize int, encrypt EncryptionOracle) (int, error) {
	max := maxBlockSize + 32
	var prevLen int
	for i := 32; i <= max; i++ {
		plaintext := make([]byte, i)
		ciphertext, err := encrypt(plaintext)
		if err != nil {
			return 0, fmt.Errorf("querying encryption oracle with chosen plaintext \"%s\": %v", plaintext, err)
		}
		if prevLen != 0 && len(ciphertext) > prevLen {
			return len(ciphertext) - prevLen, nil
		}
		prevLen = len(ciphertext)
	}
	return 0, ErrUnableToDetectBlockSize
}
