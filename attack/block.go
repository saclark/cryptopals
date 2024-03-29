package attack

import (
	"errors"
	"fmt"
)

var ErrUnableToDetectBlockSize = errors.New("attack: unable to detect block size")

// TODO: Improve so this will always work for oracles that add other data.
func DetectOracleBlockSize(maxBlockSize int, encrypt EncryptionOracle) (int, error) {
	// Most block sizes are a power of 2, so we'll start at 128, which should
	// reveal the block size in only two queries to the oracle if the block
	// size is any power of 2 <= 128.
	var prevLen int
	for i := 128; i <= 128+maxBlockSize; i++ {
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
