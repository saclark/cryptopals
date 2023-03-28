package testutil

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
)

func MustHexDecodeString(s string) []byte {
	return Must(hex.DecodeString(s))
}

func MustHexDecodeFileLines(filepath string) [][]byte {
	return Must(hexDecodeFileLines(filepath))
}

func hexDecodeFileLines(filepath string) ([][]byte, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("opening file: %v", err)
	}
	defer file.Close()

	var lines [][]byte
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		hexStr := scanner.Text()
		line, err := hex.DecodeString(hexStr)
		if err != nil {
			return nil, fmt.Errorf("hex decoding line '%s': %v", hexStr, err)
		}
		lines = append(lines, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning file: %v", err)
	}

	return lines, nil
}

func MustBase64DecodeString(s string) []byte {
	return Must(base64.StdEncoding.DecodeString(s))
}

func MustBase64DecodeFile(filepath string) []byte {
	return Must(base64DecodeFile(filepath))
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

func MustBase64DecodeFileLines(filepath string) [][]byte {
	return Must(base64DecodeFileLines(filepath))
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
