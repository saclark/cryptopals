// # Break fixed-nonce CTR statistically
//
// [In this file] find a similar set of Base64'd plaintext. Do with them exactly
// what you did with the first, but solve the problem differently.
//
// Instead of making spot guesses at to known plaintext, treat the collection of
// ciphertexts the same way you would repeating-key XOR.
//
// Obviously, CTR encryption appears different from repeated-key XOR, _but with
// a fixed nonce they are effectively the same thing_.
//
// To exploit this: take your collection of ciphertexts and truncate them to a
// common length (the length of the smallest ciphertext will work).
//
// Solve the resulting concatenation of ciphertexts as if for repeating- key
// XOR, with a key size of the length of the ciphertext you XOR'd.
//
// [In this file]: github.com/saclark/cryptopals-go/set3/data/20.txt

package set3

import "github.com/saclark/cryptopals-go/attack"

// Welp, turns out my approach for challenge 19 was the same approach sought by
// this challenge. So I'm just reusing the same solution I used for challenge
// 19.
func CrackFixedNonceCTRCiphertextsStatistically(ciphertexts [][]byte) [][]byte {
	result := attack.CrackFixedNonceCTR(ciphertexts)
	// reviewResult(result)

	result.UpdateWithPlaintextGuess(26, []byte("You want to hear some sounds that not only pounds but please your eardrums; / I sit back and observe the whole scenery"))
	// reviewResult(result)

	return result.Plaintexts
}
