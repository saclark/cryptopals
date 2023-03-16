// # Detect single-character XOR
//
// One of the 60-character strings in this file has been encrypted by
// single-character XOR.
//
// Find it.
//
// (Your code from #3 should help.)

package set1

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/saclark/cryptopals-go/attack"
	"github.com/saclark/cryptopals-go/xor"
)

func DetectAndCrackSingleByteXOREncryptedLine(filepath string) ([]byte, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("opening file: %v", err)
	}
	defer file.Close()

	var plaintext []byte
	var maxScore float64
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		hexStr := scanner.Text()
		line, err := hex.DecodeString(hexStr)
		if err != nil {
			return nil, fmt.Errorf("hex decoding line '%s': %v", hexStr, err)
		}
		key, s := attack.DetectRepeatingByteXORKey(line)
		if s >= maxScore {
			maxScore = s
			plaintext = make([]byte, len(line))
			xor.BytesRepeatingByte(plaintext, line, key)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning file: %v", err)
	}

	return plaintext, nil
}
