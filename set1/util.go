package set1

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
)

func hexMustDecodeString(s string) []byte {
	b, err := hex.DecodeString(s)
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
