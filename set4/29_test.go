package set4

import (
	"testing"

	"github.com/saclark/cryptopals/internal/testutil"
	"github.com/saclark/cryptopals/sha1"
)

func TestChallenge29(t *testing.T) {
	oracle := NewHMACSHA1Oracle()
	cookie, mac := oracle.AuthenticatedCookie()

	forgedCookie, forgedMAC, ok := ForgeHMACSHA1AuthenticatedAdminCookie(cookie, mac, 16, oracle.VerifyCookie)
	if !ok {
		t.Fatal("Failed to forge HMAC-SHA-1 authenticated admin cookie")
	}
	if !oracle.VerifyCookie(forgedCookie, forgedMAC) {
		t.Fatalf("Invalid MAC '%x' for cookie '%s'", forgedMAC, forgedCookie)
	}
}

type HMACSHA1Oracle struct {
	key []byte
}

func NewHMACSHA1Oracle() *HMACSHA1Oracle {
	return &HMACSHA1Oracle{
		key: testutil.MustRandomBytes(testutil.MustRandomInt(15) + 1),
	}
}

func (o *HMACSHA1Oracle) AuthenticatedCookie() (cookie []byte, mac sha1.Digest) {
	cookie = []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
	mac = sha1.Sum(append(o.key, cookie...))
	return cookie, mac
}

func (o *HMACSHA1Oracle) VerifyCookie(cookie []byte, mac sha1.Digest) bool {
	return sha1.Sum(append(o.key, cookie...)) == mac
}
