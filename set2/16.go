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

	"github.com/saclark/cryptopals/xor"
)

// ForgeAdminRoleCBC uses the properties of an unauthenticated AES-CBC
// ciphertext produced by an oracle to edit the ciphertext such that it decrypts
// to some desired plaintext. In this case, we are trying to inject the string
// ";admin=true" into the plaintext.
//
// Given two consecutive plaintext blocks, p1 and p2, and their corresponding
// ciphertext blocks, c1 and c2. Block p2 is computed as:
//
//	p2 = Decrypt(c2) ⊕ c1
//
// We want to change c1 to a new value c1', such that we obtain a new value of
// p2, p2' = ";admin=true" (we don't care what p1 becomes). Since we are able to
// choose p2, one way to do this would be to to set p2 to all 0x00 bytes, such
// that:
//
//	p2 = Decrypt(c2) ⊕ c1
//	0x00 = Decrypt(c2) ⊕ c1
//	Decrypt(c2) = c1 ⊕ 0x00
//	Decrypt(c2) = c1
//
// This means that for the resulting ciphertext blocks, c1 and c2, we know that
// Decrypt(c2) = c1. With this knowledge, we can edit the value of c1 to some
// c1', such that we get a new value for p2, p2' = ";admin=true".
//
//	p2 = Decrypt(c2) ⊕ c1
//	p2' = Decrypt(c2) ⊕ c1'
//	p2' = c1 ⊕ c1'
//	p2' = c1 ⊕ (c1 ⊕ ";admin=true")
//	p2' = ";admin=true"
//
// Alternatively, if we were not able to _choose_ the value of p2 but we still
// _know_ the value of p2, we could still accomplish this. Given:
//
//	p2 = Decrypt(c2) ⊕ c1
//	Decrypt(c2) = p2 ⊕ c1
//
// We can edit c1 to c1' like so:
//
//	p2 = Decrypt(c2) ⊕ c1
//	p2' = Decrypt(c2) ⊕ c1'
//	p2' = Decrypt(c2) ⊕ (Decrypt(c2) ⊕ ";admin=true")
//	p2' = (p2 ⊕ c1) ⊕ ((p2 ⊕ c1) ⊕ ";admin=true")
//	p2' = ";admin=true"
//
// Since it's simpler, we'll go the p2 = 0x00 route. Conveniently,
// "comment1=cooking%20MCs;userdata=" is 32 bytes, so our input will start
// block-aligned. We'll input 27 0x00 bytes, the first 16 of which correspond to
// the ciphertext block we will edit and the last 11 of which will be
// transformed into our target plaintext.
//
//	comment1=cooking%20MCs;userdata=000000000000000000000000000;comme...
//	|--------------||--------------||--------------||--------------||---
func ForgeAdminRoleCBC(oracle func(string) ([]byte, error)) ([]byte, error) {
	input := make([]byte, 27)
	ciphertext, err := oracle(string(input))
	if err != nil {
		return nil, fmt.Errorf("querying oracle wth \"%x\"", input)
	}
	xor.BytesFixed(ciphertext[32:43], ciphertext[32:43], []byte(";admin=true"))
	return ciphertext, nil
}
