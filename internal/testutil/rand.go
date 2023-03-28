package testutil

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

func MustRandomBytes(n int) []byte {
	return Must(randomBytes(n))
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("reading %d random bytes: %v", n, err)
	}
	return b, nil
}

func MustReadRandomBytes(b []byte) int {
	return Must(readRandomBytes(b))
}

func readRandomBytes(b []byte) (int, error) {
	n, err := rand.Read(b)
	if err != nil {
		return 0, fmt.Errorf("reading %d random bytes: %v", len(b), err)
	}
	return n, nil
}

func MustRandomBool() bool {
	return Must(randomBool())
}

func randomBool() (bool, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(2))
	if err != nil {
		return false, fmt.Errorf("generating random int in range [0, 2): %v", err)
	}
	return n.Int64() == 1, nil
}

func MustRandomInt(max int) int {
	return Must(randomInt(max))
}

func randomInt(max int) (int, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, fmt.Errorf("generating random int in range [0, %d): %v", max, err)
	}
	return int(n.Int64()), nil
}
