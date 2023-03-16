// # CBC bitflipping attacks
//
// Generate a random AES key.
//
// Combine your padding code and CBC code to write two functions.
//
// The first function should take an arbitrary input string, prepend the string:
//
// 	"comment1=cooking%20MCs;userdata="
//
// .. and append the string:
//
// 	";comment2=%20like%20a%20pound%20of%20bacon"
//
// The function should quote out the ";" and "=" characters.
//
// The function should then pad out the input to the 16-byte AES block length
// and encrypt it under the random AES key.
//
// The second function should decrypt the string and look for the characters
// ";admin=true;" (or, equivalently, decrypt, split the string on ";", convert
// each resulting string into 2-tuples, and look for the "admin" tuple).
//
// Return true or false based on whether the string exists.
//
// If you've written the first function properly, it should _not_ be possible to
// provide user input to it that will generate the string the second function is
// looking for. We'll have to break the crypto to do that.
//
// Instead, modify the ciphertext (without knowledge of the AES key) to
// accomplish this.
//
// You're relying on the fact that in CBC mode, a 1-bit error in a ciphertext
// block:
//
// * Completely scrambles the block the error occurs in
// * Produces the identical 1-bit error(/edit) in the next ciphertext block.
//
// > # Stop and think for a second.
// > Before you implement this attack, answer this question: why does CBC mode
// > have this property?

package set2

import (
	"fmt"
	"strings"

	"github.com/saclark/cryptopals-go/aes"
	"github.com/saclark/cryptopals-go/pkcs7"
	"github.com/saclark/cryptopals-go/xor"
)

// Given two consecutive plaintext blocks, A and B, and their corresponding
// ciphertext blocks, X and Y:
//
//	Plaintext : A B
//	Ciphertext: X Y
//
// Block B is computed as:
//
//	B = Decrypt(Y) ⊕ X
//
// We want to change X to a new value X', such that we obtain a new value of B,
// B' = ";admin=true" (we don't care what A becomes). Since we are able to
// choose B, one way to do this would be to to set B to all 0x00 bytes, such
// that:
//
//	B = Decrypt(Y) ⊕ X
//	0x00 = Decrypt(Y) ⊕ X
//	Decrypt(Y) = X ⊕ 0x00
//	Decrypt(Y) = X
//
// This means that for the resulting ciphertext blocks, X and Y, we know that
// Decrypt(Y) = X. With this knowledge, we can edit the value of X to some X',
// such that we get a new value for B, B' = ";admin=true".
//
//	B = Decrypt(Y) ⊕ X
//	B' = Decrypt(Y) ⊕ X'
//	B' = X ⊕ X'
//	B' = X ⊕ (X ⊕ ";admin=true")
//	B' = ";admin=true"
//
// Alternatively, if we were not able to _choose_ the value of B but we still
// _know_ the value of B, we could still accomplish this. Given:
//
//	B = Decrypt(Y) ⊕ X
//	Decrypt(Y) = B ⊕ X
//
// We can edit X to X' like so:
//
//	B = Decrypt(Y) ⊕ X
//	B' = Decrypt(Y) ⊕ X'
//	B' = Decrypt(Y) ⊕ (Decrypt(Y) ⊕ ";admin=true")
//	B' = (B ⊕ X) ⊕ ((B ⊕ X) ⊕ ";admin=true")
//	B' = ";admin=true"
//
// Since it's simpler, we'll go the B = 0x00 route.
func ForgeAdminRoleCBC(oracle func(string) ([]byte, error)) ([]byte, error) {
	// Conveniently, "comment1=cooking%20MCs;userdata=" is 32 bytes, so our
	// input will start block-aligned. We'll input 27 0x00 bytes, the first 16
	// of which correspond to the ciphertext block we will edit and the last 11
	// of which will be transformed into our target plaintext.
	// comment1=cooking%20MCs;userdata=000000000000000000000000000;comme...
	// |--------------||--------------||--------------||--------------||---
	input := make([]byte, 27)
	ciphertext, err := oracle(string(input))
	if err != nil {
		return nil, fmt.Errorf("querying oracle wth \"%x\"", input)
	}
	xor.BytesFixed(ciphertext[32:43], ciphertext[32:43], []byte(";admin=true"))
	return ciphertext, nil
}

// CBCBitFlippingOracle implements an encryption oracle that takes some input,
// escapes any ";" and "=" characters, injects it into the string:
//
//	comment1=cooking%20MCs;userdata={input};comment2=%20like%20a%20pound%20of%20bacon
//
// and then encrypts that using AES in CBC mode under the same key and IV upon
// each invocation. An attacker should be able to use this oracle to craft a
// ciphertext that decrypts to a plaintext containing ";admin=true;". Attackers
// can use Key and IV to verify their attacks.
type CBCBitFlippingOracle struct {
	Key []byte
	IV  []byte
}

// NewCBCBitFlippingOracle creates a new CBCBitFlippingOracle with a randomly
// generated Key and IV.
func NewCBCBitFlippingOracle() (*CBCBitFlippingOracle, error) {
	key, err := randomBytes(aes.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("generating random key: %w", err)
	}
	iv, err := randomBytes(aes.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("generating random IV: %w", err)
	}
	return &CBCBitFlippingOracle{Key: key, IV: iv}, nil
}

// EncryptUserComments acts as the encryption oracle.
func (o *CBCBitFlippingOracle) EncryptUserComments(userData string) ([]byte, error) {
	userData = strings.ReplaceAll(userData, ";", "%3B")
	userData = strings.ReplaceAll(userData, "=", "%3D")
	plaintext := []byte("comment1=cooking%20MCs;userdata=" + userData + ";comment2=%20like%20a%20pound%20of%20bacon")
	plaintext = pkcs7.Pad(plaintext, aes.BlockSize)
	return aes.EncryptCBC(plaintext, o.Key, o.IV)
}
