// # Break a SHA-1 keyed MAC using length extension
//
// Secret-prefix SHA-1 MACs are trivially breakable.
//
// The attack on secret-prefix SHA1 relies on the fact that you can take the
// ouput of SHA-1 and use it as a new starting point for SHA-1, thus taking an
// arbitrary SHA-1 hash and "feeding it more data".
//
// Since the key precedes the data in secret-prefix, any additional data you
// feed the SHA-1 hash in this fashion will appear to have been hashed with the
// secret key.
//
// To carry out the attack, you'll need to account for the fact that SHA-1 is
// "padded" with the bit-length of the message; your forged message will need to
// include that padding. We call this "glue padding". The final message you
// actually forge will be:
//
// 	SHA1(key || original-message || glue-padding || new-message)
//
// (where the final padding on the whole constructed message is implied)
//
// Note that to generate the glue padding, you'll need to know the original bit
// length of the message; the message itself is known to the attacker, but the
// secret key isn't, so you'll need to guess at it.
//
// This sounds more complicated than it is in practice.
//
// To implement the attack, first write the function that computes the MD
// padding of an arbitrary message and verify that you're generating the same
// padding that your SHA-1 implementation is using. This should take you 5-10
// minutes.
//
// Now, take the SHA-1 secret-prefix MAC of the message you want to forge ---
// this is just a SHA-1 hash --- and break it into 32 bit SHA-1 registers
// (SHA-1 calls them "a", "b", "c", &c).
//
// Modify your SHA-1 implementation so that callers can pass in new values for
// "a", "b", "c" &c (they normally start at magic numbers). With the registers
// "fixated", hash the additional data you want to forge.
//
// Using this attack, generate a secret-prefix MAC under a secret key (choose a
// random word from /usr/share/dict/words or something) of the string:
//
// 	"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
//
// Forge a variant of this message that ends with ";admin=true".
//
// > # This is a very useful attack.
// > For instance: Thai Duong and Juliano Rizzo, who got to this attack before
// we did, used it to break the Flickr API.

package set4

import (
	"bytes"
	"encoding/binary"

	"github.com/saclark/cryptopals/sha1"
)

func ForgeHMACSHA1AuthenticatedAdminCookie(
	cookie []byte,
	cookieMAC sha1.Digest,
	maxKeyLen int,
	verifyCookie func([]byte, sha1.Digest) bool,
) (forgedCookie []byte, forgeMAC sha1.Digest, ok bool) {
	adminText := []byte(";admin=true")

	for keyLen := maxKeyLen; keyLen >= 0; keyLen-- {
		origLen := uint64(keyLen + len(cookie))
		pad := computeSHA1Padding(origLen)
		initLen := origLen + uint64(len(pad))

		var h [5]uint32
		for i := 0; i < 5; i++ {
			h[i] = binary.BigEndian.Uint32(cookieMAC[i*4 : (i*4)+4])
		}

		forgeMAC := sha1.SumFromHashState(h, initLen, adminText)
		forgedCookie := append(bytes.Clone(cookie), append(pad, adminText...)...)

		if verifyCookie(forgedCookie, forgeMAC) {
			return forgedCookie, forgeMAC, true
		}
	}

	return nil, sha1.Digest{}, false
}

func computeSHA1Padding(msgLen uint64) []byte {
	padLen := sha1.BlockSize - (msgLen % sha1.BlockSize)
	if padLen < 9 {
		padLen += sha1.BlockSize
	}

	pad := make([]byte, padLen)
	pad[0] = 0x80
	binary.BigEndian.PutUint64(pad[len(pad)-8:], msgLen*8)

	return pad
}
