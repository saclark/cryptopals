package set3

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"os"
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

func base64MustDecodeString(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func base64DecodeFileLines(filepath string) ([][]byte, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("opening file: %v", err)
	}
	defer file.Close()

	var decodedLines [][]byte
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		decoded, err := base64.StdEncoding.DecodeString(line)
		if err != nil {
			return nil, fmt.Errorf("base64 decoding line '%s': %v", line, err)
		}
		decodedLines = append(decodedLines, decoded)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning file: %v", err)
	}

	return decodedLines, nil
}
