// # Implement CBC mode
//
// CBC mode is a block cipher mode that allows us to encrypt irregularly-sized
// messages, despite the fact that a block cipher natively only transforms
// individual blocks.
//
// In CBC mode, each ciphertext block is added to the next plaintext block
// before the next call to the cipher core.
//
// The first plaintext block, which has no associated previous ciphertext block,
// is added to a "fake 0th ciphertext block" called the _initialization vector_,
// or IV.
//
// Implement CBC mode by hand by taking the ECB function you wrote earlier,
// making it _encrypt_ instead of _decrypt_ (verify this by decrypting whatever
// you encrypt to test), and using your XOR function from the previous exercise
// to combine them.
//
// The file here is intelligible (somewhat) when CBC decrypted against
// "YELLOW SUBMARINE" with an IV of all ASCII 0 (\x00\x00\x00 &c)
//
// > # Don't cheat.
// > Do not use OpenSSL's CBC code to do CBC mode, even to verify your results.
// > What's the point of even doing this stuff if you aren't going to learn from
// > it?

package set2

import (
	"fmt"

	"github.com/saclark/cryptopals-go/cipher"
)

func AESCBCDecryptFile(filepath string, key, iv []byte) ([]byte, error) {
	decoded, err := base64DecodeFile(filepath)
	if err != nil {
		return nil, err
	}

	plaintext, err := cipher.CBCDecrypt(decoded, key, iv)
	if err != nil {
		return nil, fmt.Errorf("decrypting file contents: %v", err)
	}

	return plaintext, err
}
