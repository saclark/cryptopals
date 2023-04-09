// # Break "random access read/write" AES CTR
//
// Back to CTR. Encrypt the recovered plaintext from [this file] (the ECB
// exercise) under CTR with a random key (for this exercise the key should be
// unknown to you, but hold on to it).
//
// Now, write the code that allows you to "seek" into the ciphertext, decrypt,
// and re-encrypt with different plaintext. Expose this as a function, like,
// "_edit(ciphertext, key, offset, newtext)_".
//
// Imagine the "edit" function was exposed to attackers by means of an API call
// that didn't reveal the key or the original plaintext; the attacker has the
// ciphertext and controls the offset and "new text".
//
// Recover the original plaintext.
//
// > # Food for thought.
// > A folkloric supposed benefit of CTR mode is the ability to easily "seek
// > forward" into the ciphertext; to access byte N of the ciphertext, all you
// > need to be able to do is generate byte N of the keystream. Imagine if you'd
// > relied on that advice to, say, encrypt a disk.
//
// [this file]: github.com/saclark/cryptopals/set4/data/25.txt

package set4

import (
	"github.com/saclark/cryptopals/xor"
)

// The easiest way to do this is to choose all 0x00 bytes as our plaintext (with
// same length as the original ciphertext). This means the resulting ciphertext
// will _be_ the keystream, since p ^ 0x00 = p. So we can XOR the original
// ciphertext with the new ciphertext (the keystream) to recover the original
// plaintext.
//
// Alternatively, we could pass in any old plaintext (with same length as the
// original ciphertext), then XOR the resulting new ciphertext with our chosen
// plaintext to recover the keystream. From there, we XOR that keystream with
// the original ciphertext to recover the original plaintext.
//
// We'll do it the easy way though.
func CrackRandomAccessReadWriteAESCTR(
	ciphertext []byte,
	oracle func(offset int, newPlaintext []byte) []byte,
) []byte {
	allZeros := make([]byte, len(ciphertext))
	keystream := oracle(0, allZeros)

	plaintext := make([]byte, len(ciphertext))
	xor.BytesFixed(plaintext, ciphertext, keystream)

	return plaintext
}
