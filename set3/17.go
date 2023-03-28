// # The CBC padding oracle
//
// This is the best-known attack on modern block-cipher cryptography.
//
// Combine your padding code and your CBC code to write two functions.
//
// The first function should select at random one of the following 10 strings:
//
// 	MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
// 	MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
// 	MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
// 	MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
// 	MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
// 	MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
// 	MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
// 	MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
// 	MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
// 	MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93
//
// ... generate a random AES key (which it should save for all future
// encryptions), pad the string out to the 16-byte AES block size and
// CBC-encrypt it under that key, providing the caller the ciphertext and IV.
//
// The second function should consume the ciphertext produced by the first
// function, decrypt it, check its padding, and return true or false depending
// on whether the padding is valid.
//
// > # What you're doing here.
// > This pair of functions approximates AES-CBC encryption as its deployed
// > serverside in web applications; the second function models the server's
// > consumption of an encrypted session token, as if it was a cookie.
//
// It turns out that it's possible to decrypt the ciphertexts provided by the
// first function.
//
// The decryption here depends on a side-channel leak by the decryption
// function. The leak is the error message that the padding is valid or not.
//
// You can find 100 web pages on how this attack works, so I won't re-explain
// it. What I'll say is this:
//
// The fundamental insight behind this attack is that the byte 01h is valid
// padding, and occur in 1/256 trials of "randomized" plaintexts produced by
// decrypting a tampered ciphertext.
//
// 02h in isolation is _not_ valid padding.
//
// 02h 02h _is_ valid padding, but is much less likely to occur randomly than
// 01h.
//
// 03h 03h 03h is even less likely.
//
// So you can assume that if you corrupt a decryption AND it had valid padding,
// you know what that padding byte is.
//
// It is easy to get tripped up on the fact that CBC plaintexts are "padded".
// _Padding oracles have nothing to do with the actual padding on a CBC
// plaintext_. It's an attack that targets a specific bit of code that handles
// decryption. You can mount a padding oracle on _any CBC block_, whether it's
// padded or not.

package set3

import (
	"fmt"

	"github.com/saclark/cryptopals-go/pkcs7"
)

// CrackCBCPaddingOracle executes a CBC padding oracle attack on a function
// that acts as a padding oracle. See the [Wikipedia article] for a decent
// explanation of how this works.
//
// [Wikipedia article]: https://en.wikipedia.org/wiki/Padding_oracle_attack
func CrackCBCPaddingOracle(
	ciphertext,
	iv []byte,
	blockSize int,
	oracle func(ciphertext, iv []byte) error,
) ([]byte, error) {
	decrypted := make([]byte, len(ciphertext))
	c1 := iv // the first ciphertext block
	for start, end := 0, blockSize; end <= len(ciphertext); start, end = start+blockSize, end+blockSize {
		c2 := ciphertext[start:end] // the second ciphertext block

		input := make([]byte, blockSize*2)
		copy(input[:blockSize], c1)
		copy(input[blockSize:], c2)

		c1Prime := input[:blockSize] // the modified first ciphertext block
		for i := len(c1Prime) - 1; i >= 0; i-- {
			var found bool
			for charCode := 0; charCode < 256; charCode++ {
				c1Prime[i] = byte(charCode)
				if err := oracle(input, iv); err != nil {
					continue
				}

				// Verify the result.
				if i > 0 {
					c1Prime[i-1] ^= 1
					if err := oracle(input, iv); err != nil {
						continue
					}
				}

				// p2' = c1' ⊕ Decrypt(c2)
				p2PrimeByte := byte(blockSize - i) // the modified plaintext byte

				// p2 = c1 ⊕ Decrypt(c2) = c1 ⊕ (c1' ⊕ p2')
				decrypted[start+i] = c1[i] ^ c1Prime[i] ^ p2PrimeByte

				// Set the new expected padding values on p2.
				for j := len(c1Prime) - 1; j >= i; j-- {
					c1Prime[j] = c1Prime[j] ^ p2PrimeByte ^ (p2PrimeByte + 1)
				}

				found = true
				break
			}

			if !found {
				return nil, fmt.Errorf("unable to decrypt byte %d. have: %s", start+i, decrypted)
			}
		}

		c1 = c2
	}

	decrypted, err := pkcs7.Unpad(decrypted, blockSize)
	if err != nil {
		return nil, fmt.Errorf("unpading decrypted result: %w", err)
	}

	return decrypted, nil
}
