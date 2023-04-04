// # Create the MT19937 stream cipher and break it
//
// You can create a trivial stream cipher out of any PRNG; use it to generate a
// sequence of 8 bit outputs and call those outputs a keystream. XOR each byte
// of plaintext with each successive byte of keystream.
//
// Write the function that does this for MT19937 using a 16-bit seed. Verify
// that you can encrypt and decrypt properly. This code should look similar to
// your CTR code.
//
// Use your function to encrypt a known plaintext (say, 14 consecutive 'A'
// characters) prefixed by a random number of random characters.
//
// From the ciphertext, recover the "key" (the 16 bit seed).
//
// Use the same idea to generate a random "password reset token" using MT19937
// seeded from the current time.
//
// Write a function to check if any given password token is actually the product
// of an MT19937 PRNG seeded with the current time.

package set3

import (
	"bytes"
	"math"
	"time"

	"github.com/saclark/cryptopals-go/rand"
)

func PRNGStreamCrypt(input []byte, seed uint32) []byte {
	output := make([]byte, len(input))
	prng := rand.NewMT19937(seed)
	mt19937Crypt(output, input, prng)
	return output
}

func RecoverMT19937StreamCipher16BitSeed(ciphertext, knownPlaintext []byte) (uint16, bool) {
	prng := &rand.MT19937{}
	b := make([]byte, len(ciphertext))
	prefixLen := len(ciphertext) - len(knownPlaintext)
	for i := uint32(0); i < math.MaxUint16; i++ {
		prng.Seed(i)
		mt19937Crypt(b, ciphertext, prng)
		if bytes.Equal(b[prefixLen:], knownPlaintext) {
			return uint16(i), true
		}
	}
	return 0, false
}

func IsTokenTimeSeededMT19937Output(token []byte, maxTimeSince time.Duration) bool {
	now := uint32(time.Now().Unix())
	t := now - uint32(maxTimeSince.Seconds()) - 5 // 5 seconds of margin
	prng := &rand.MT19937{}
	b := make([]byte, len(token))
	for ; t <= now; t++ {
		prng.Seed(t)
		readMT19937Bytes(b, prng)
		if bytes.Equal(token, b) {
			return true
		}
	}
	return false
}

func mt19937Crypt(dst, src []byte, prng *rand.MT19937) {
	if len(dst) < len(src) {
		panic("output smaller than input")
	}
	for i := 0; i < len(src); i++ {
		dst[i] = src[i] ^ byte(prng.Uint32()%255)
	}
}

func readMT19937Bytes(dst []byte, prng *rand.MT19937) {
	for i := 0; i < len(dst); i++ {
		dst[i] = byte(prng.Uint32() % 255)
	}
}
