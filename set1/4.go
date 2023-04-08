// # Detect single-character XOR
//
// One of the 60-character strings in [this file] has been encrypted by
// single-character XOR.
//
// Find it.
//
// (Your code from #3 should help.)
//
// [this file]: github.com/saclark/cryptopals/set1/data/4.txt

package set1

import (
	"github.com/saclark/cryptopals/attack"
	"github.com/saclark/cryptopals/xor"
)

func DetectAndCrackSingleByteXOREncryptedLine(lines [][]byte) ([]byte, error) {
	var plaintext []byte
	var maxScore float64
	for _, line := range lines {
		key, s := attack.DetectRepeatingByteXORKey(line)
		if s >= maxScore {
			maxScore = s
			plaintext = make([]byte, len(line))
			xor.BytesRepeatingByte(plaintext, line, key)
		}
	}
	return plaintext, nil
}
