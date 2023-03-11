package oracle

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

func randomBlock(blockSize int) ([]byte, error) {
	block := make([]byte, blockSize)
	if _, err := rand.Read(block); err != nil {
		return nil, fmt.Errorf("reading %d random bytes: %v", blockSize, err)
	}
	return block, nil
}

func randomMode() (Mode, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(2))
	if err != nil {
		return 0, fmt.Errorf("generating random int in range [0, 2): %v", err)
	}
	if n.Int64() == 0 {
		return ModeECB, nil
	}
	return ModeCBC, nil
}
