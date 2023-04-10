// # CTR bitflipping
//
// There are people in the world that believe that CTR resists bit flipping
// attacks of the kind to which CBC mode is susceptible.
//
// Re-implement [the CBC bitflipping exercise from earlier] to use CTR mode
// instead of CBC mode. Inject an "admin=true" token.
//
// [the CBC bitflipping exercise from earlier]: github.com/saclark/cryptopals/set2/16.go

package set4

import (
	"github.com/saclark/cryptopals/xor"
)

// Similar to challenge 25, we inject a string of 0x00 bytes the same length as
// the plaintext we wish to inject. This means the corresponding ciphertext
// bytes will be the same as that section of keystream. We then just have to set
// those particular ciphertext bytes to the XOR of those bytes with the
// plaintext we wish to inject. When decrypted, the resulting plaintext will
// then include our injected plaintext, ";admin=true".
func ForgeAdminRoleCTR(oracle func(string) []byte) []byte {
	plaintextInjection := []byte(";admin=true")
	allZeros := make([]byte, len(plaintextInjection))
	ciphertext := oracle(string(allZeros))
	xor.BytesFixed(ciphertext[32:43], ciphertext[32:43], plaintextInjection)
	return ciphertext
}
