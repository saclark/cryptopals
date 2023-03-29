// # Detect AES in ECB mode
//
// [In this file] are a bunch of hex-encoded ciphertexts.
//
// One of them has been encrypted with ECB.
//
// Detect it.
//
// Remember that the problem with ECB is that it is stateless and deterministic;
// the same 16 byte plaintext block will always produce the same 16 byte
// ciphertext.
//
// [In this file]: github.com/saclark/cryptopals-go/set1/data/8.txt

package set1

import (
	"crypto/aes"

	"github.com/saclark/cryptopals-go/attack"
)

func FindAESECBEncryptedCiphertext(ciphertexts [][]byte) []byte {
	var ecbCiphertext []byte
	var maxScore float64
	for _, ciphertext := range ciphertexts {
		s := attack.DetectECBMode(ciphertext, aes.BlockSize)
		if s > maxScore {
			ecbCiphertext = ciphertext
			maxScore = s
		}
	}
	return ecbCiphertext
}
