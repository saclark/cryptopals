// # Implement a SHA-1 keyed MAC
//
// Find a SHA-1 implementation in the language you code in.
//
// > # Don't cheat. It won't work.
// > Do not use the SHA-1 implementation your language already provides (for
// > instance, don't use the "Digest" library in Ruby, or call OpenSSL; in Ruby,
// > you'd want a pure-Ruby SHA-1).
//
// Write a function to authenticate a message under a secret key by using a
// secret-prefix MAC, which is simply:
//
// 	SHA1(key || message)
//
// Verify that you cannot tamper with the message without breaking the MAC
// you've produced, and that you can't produce a new MAC without knowing the
// secret key.

package set4

import "github.com/saclark/cryptopals/sha1"

// Not sure if the challenge was actually asking us to implement SHA-1 ourselves
// but I did it anyway since it sounded fun and figured I'd learn more that way.
func SecretPrefixHMACSHA1(message, key []byte) [sha1.Size]byte {
	return sha1.Sum(append(key, message...))
}
