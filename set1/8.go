// # Detect AES in ECB mode
//
// In this file are a bunch of hex-encoded ciphertexts.
//
// One of them has been encrypted with ECB.
//
// Detect it.
//
// Remember that the problem with ECB is that it is stateless and deterministic;
// the same 16 byte plaintext block will always produce the same 16 byte
// ciphertext.

package set1

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/saclark/cryptopals-go/aes"
	"github.com/saclark/cryptopals-go/attack"
)

func FindAESECBEncryptedLine(filepath string) (string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return "", fmt.Errorf("opening file: %v", err)
	}
	defer file.Close()

	var encryptedLine string
	var maxScore float64
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		b, err := hex.DecodeString(line)
		if err != nil {
			return "", fmt.Errorf("hex decoding line '%s': %v", line, err)
		}
		s := attack.DetectECBMode(b, aes.BlockSize)
		if s > maxScore {
			encryptedLine = line
			maxScore = s
		}
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("scanning file: %v", err)
	}

	return encryptedLine, nil
}
