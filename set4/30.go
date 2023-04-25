// # Break an MD4 keyed MAC using length extension
//
// Second verse, same as the first, but use MD4 instead of SHA-1. Having done
// this attack once against SHA-1, the MD4 variant should take much less time;
// mostly just the time you'll spend Googling for an implementation of MD4.
//
// > # You're thinking, why did we bother with this?
// > Blame Stripe. In their second CTF game, the second-to-last challenge
// > involved breaking an H(k, m) MAC with SHA1. Which meant that SHA1 code was
// > floating all over the Internet. MD4 code, not so much.

package set4

import (
	"bytes"
	"encoding/binary"

	"github.com/saclark/cryptopals/md4"
)

func ForgeHMACMD4AuthenticatedAdminCookie(
	cookie []byte,
	cookieMAC md4.Digest,
	maxKeyLen int,
	verifyCookie func([]byte, md4.Digest) bool,
) (forgedCookie []byte, forgeMAC md4.Digest, ok bool) {
	adminText := []byte(";admin=true")

	for keyLen := maxKeyLen; keyLen >= 0; keyLen-- {
		origLen := uint64(keyLen + len(cookie))
		pad := computeMD4Padding(origLen)
		initLen := origLen + uint64(len(pad))

		var r [4]uint32
		for i := 0; i < 4; i++ {
			r[i] = binary.LittleEndian.Uint32(cookieMAC[i*4 : (i*4)+4])
		}

		forgeMAC := md4.SumFromHashState(r, initLen, adminText)
		forgedCookie := append(bytes.Clone(cookie), append(pad, adminText...)...)

		if verifyCookie(forgedCookie, forgeMAC) {
			return forgedCookie, forgeMAC, true
		}
	}

	return nil, md4.Digest{}, false
}

func computeMD4Padding(msgLen uint64) []byte {
	padLen := md4.BlockSize - (msgLen % md4.BlockSize)
	if padLen < 9 {
		padLen += md4.BlockSize
	}

	pad := make([]byte, padLen)
	pad[0] = 0x80
	binary.LittleEndian.PutUint64(pad[len(pad)-8:], msgLen*8)

	return pad
}
