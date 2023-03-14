package set2

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
)

func base64MustDecodeString(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func base64DecodeFile(filepath string) ([]byte, error) {
	fileBytes, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("reading file: %v", err)
	}
	decoded := make([]byte, len(fileBytes))
	n, err := base64.StdEncoding.Decode(decoded, fileBytes)
	if err != nil {
		return nil, fmt.Errorf("base64 decoding file: %v", err)
	}
	return decoded[:n], nil
}

func randomBlock(blockSize int) ([]byte, error) {
	block := make([]byte, blockSize)
	if _, err := rand.Read(block); err != nil {
		return nil, fmt.Errorf("reading %d random bytes: %v", blockSize, err)
	}
	return block, nil
}
