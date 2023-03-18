package set3

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("reading %d random bytes: %v", n, err)
	}
	return b, nil
}

func randomInt(max int) (int, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, fmt.Errorf("generating random int in range [0, %d): %v", max, err)
	}
	return int(n.Int64()), nil
}
