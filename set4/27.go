// # Recover the key from CBC with IV=Key
//
// Take your code from [the CBC exercise] and modify it so that it repurposes the
// key for CBC encryption as the IV.
//
// Applications sometimes use the key as an IV on the auspices that both the
// sender and the receiver have to know the key already, and can save some space
// by using it as both a key and an IV.
//
// Using the key as an IV is insecure; an attacker that can modify ciphertext in
// flight can get the receiver to decrypt a value that will reveal the key.
//
// The CBC code from exercise 16 encrypts a URL string. Verify each byte of the
// plaintext for ASCII compliance (ie, look for high-ASCII values). Noncompliant
// messages should raise an exception or return an error that includes the
// decrypted plaintext (this happens all the time in real systems, for what it's
// worth).
//
// Use your code to encrypt a message that is at least 3 blocks long:
//
// 	AES-CBC(P_1, P_2, P_3) -> C_1, C_2, C_3
//
// Modify the message (you are now the attacker):
//
// 	C_1, C_2, C_3 -> C_1, 0, C_1
//
// Decrypt the message (you are now the receiver) and raise the appropriate
// error if high-ASCII is found.
//
// As the attacker, recovering the plaintext from the error, extract the key:
//
// 	P'_1 XOR P'_3
//
// [the CBC exercise]: github.com/saclark/cryptopals/set2/16.go

package set4

import (
	"bytes"
	"crypto/aes"
	"fmt"
	"strings"

	"github.com/saclark/cryptopals/xor"
)

// RecoverKeyFromCBCIVIsKeyOracle recovers the key used to AES-CBC encrypt a
// plaintext given an encryption and decryption oracle that repurposes the key
// as the IV and returns the decrypted plaintext in the error message when the
// decrypted plaintext is not valid ASCII.
//
// To do so, we pass 3 blocks of any bytes, plus two blocks of 0x00 bytes to the
// encryption oracle. On the returned ciphertext, we then set the 2nd ciphertext
// block to all 0x00 bytes and the 3rd ciphertext block to equal the 1st
// ciphertext block. When decrypted this means that:
//
//	p1 = iv ^ D(c1)
//	p2 = c1 ^ D(c2') = c1 ^ D(0x00)
//	p3 = c2' ^ D(c3') = 0x00 ^ D(c1) = D(c1)
//
// Which means we can recover the key from the resulting plaintext via p1 ^ p3:
//
//	p1 ^ p3 = iv ^ D(c1) ^ D(c1) = iv = key
//
// However, we need to ensure the decryption oracle returns an error (so we can
// get back the plaintext) and that our ciphertext decrypts to a proper PKCS#7
// padded plaintext. This is why we had set the last two blocks of our original
// plaintext to all 0x00 bytes. Using the same trick utilized in [challenge 16],
// those final 0x00 byte blocks mean we can set the value of the final resulting
// plaintext block by XORing the 2nd to last ciphertext block with our desired
// plaintext. In this case, that'll be a bunch of non-ASCII bytes (e.g. 0xff, so
// that the decryption oracle will return an error containing the plaintext),
// ending with a single 0x01 byte (so that the resulting plaintext is properly
// padded). We pass our modified ciphertext to the decryption oracle, get back
// the error, extrack the plaintext from the error message, XOR p1 with p2,
// and voilà, we have they key.
//
// [challenge 16]: github.com/saclark/cryptopals/set2/16.go
func RecoverKeyFromCBCIVIsKeyOracle(
	encryptionOracle func([]byte) []byte,
	decryptionOracle func([]byte) error,
) ([]byte, error) {
	k := aes.BlockSize

	ciphertext := encryptionOracle(make([]byte, k*5))

	// c1, c2, c3 -> c1, 0x00..., c1
	copy(ciphertext[k:k*2], make([]byte, k))
	copy(ciphertext[k*2:k*3], ciphertext[:k])

	// Ensure the ciphertext decrypts to a properly padded, non-ASCII plaintext.
	xor.BytesFixed(
		ciphertext[k*3:k*4],
		ciphertext[k*3:k*4],
		append(bytes.Repeat([]byte{0xff}, aes.BlockSize-1), 0x01),
	)

	err := decryptionOracle(ciphertext)
	if err == nil {
		return nil, fmt.Errorf("unable to recover key: decrypted successfully")
	} else if !strings.HasPrefix(err.Error(), "not valid ASCII: ") {
		return nil, fmt.Errorf("unable to recover key: %v", err)
	}

	key := make([]byte, k)
	plaintext := []byte(strings.TrimPrefix(err.Error(), "not valid ASCII: "))
	xor.BytesFixed(key, plaintext[:k], plaintext[k*2:k*3])

	return key, nil
}
