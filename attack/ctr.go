package attack

import (
	"github.com/saclark/cryptopals/xor"
)

type FixedNonceCTRCrackResult struct {
	Ciphertexts [][]byte
	Plaintexts  [][]byte
	Keystream   []byte
}

func CrackFixedNonceCTR(ciphertexts [][]byte) FixedNonceCTRCrackResult {
	c := FixedNonceCTRCrackResult{
		Ciphertexts: ciphertexts,
		Plaintexts:  make([][]byte, len(ciphertexts)),
	}

	for i := 0; ; i++ {
		var b []byte
		for _, ciphertext := range c.Ciphertexts {
			if i < len(ciphertext) {
				b = append(b, ciphertext[i])
			}
		}
		if len(b) == 0 {
			break
		}
		k, _ := DetectRepeatingByteXORKey(b)
		c.Keystream = append(c.Keystream, k)
	}

	for i, ciphertext := range c.Ciphertexts {
		c.Plaintexts[i] = make([]byte, len(c.Ciphertexts[i]))
		xor.BytesFixed(c.Plaintexts[i], ciphertext, c.Keystream[:len(ciphertext)])
	}

	return c
}

func (c *FixedNonceCTRCrackResult) UpdateWithPlaintextGuess(i int, guess []byte) {
	xor.BytesFixed(c.Keystream, c.Ciphertexts[i], guess)
	for i, ciphertext := range c.Ciphertexts {
		xor.BytesFixed(c.Plaintexts[i], ciphertext, c.Keystream[:len(ciphertext)])
	}
}
