package set4

import (
	"testing"

	"github.com/saclark/cryptopals/internal/testutil"
	"github.com/saclark/cryptopals/md4"
)

func TestChallenge30(t *testing.T) {
	oracle := NewHMACMD4Oracle()
	cookie, mac := oracle.AuthenticatedCookie()

	forgedCookie, forgedMAC, ok := ForgeHMACMD4AuthenticatedAdminCookie(cookie, mac, 16, oracle.VerifyCookie)
	if !ok {
		t.Fatal("Failed to forge HMAC-MD4 authenticated admin cookie")
	}
	if !oracle.VerifyCookie(forgedCookie, forgedMAC) {
		t.Fatalf("Invalid MAC '%x' for cookie '%s'", forgedMAC, forgedCookie)
	}

}

type HMACMD4Oracle struct {
	key []byte
}

func NewHMACMD4Oracle() *HMACMD4Oracle {
	return &HMACMD4Oracle{
		key: testutil.MustRandomBytes(testutil.MustRandomInt(15) + 1),
	}
}

func (o *HMACMD4Oracle) AuthenticatedCookie() (cookie []byte, mac md4.Digest) {
	cookie = []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
	mac = md4.Sum(append(o.key, cookie...))
	return cookie, mac
}

func (o *HMACMD4Oracle) VerifyCookie(cookie []byte, mac md4.Digest) bool {
	return md4.Sum(append(o.key, cookie...)) == mac
}
