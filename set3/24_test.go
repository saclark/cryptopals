package set3

import (
	"bytes"
	"math"
	"testing"
	"time"

	"github.com/saclark/cryptopals/internal/testutil"
	"github.com/saclark/cryptopals/rand"
)

func TestChallenge24_PRNGStreamCipher(t *testing.T) {
	seed := uint32(testutil.MustRandomInt(math.MaxUint16))
	plaintext := []byte("2q478yq@*6q2AAAAAAAAAAAAAA")
	encrypted := PRNGStreamCrypt(plaintext, seed)
	decrypted := PRNGStreamCrypt(encrypted, seed)

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("want: '%x', got: '%x'", plaintext, decrypted)
	}
}

func TestChallenge24_Recover16BitSeed(t *testing.T) {
	knownPlaintext := []byte("AAAAAAAAAAAAAA")
	ciphertext, wantSeed := prefixAndMT19937StreamEncrypt(knownPlaintext)
	got, ok := RecoverMT19937StreamCipher16BitSeed(ciphertext, knownPlaintext)

	if !ok {
		t.Fatal("failed to recover 16-bit MT19937 stream cipher seed")
	}
	if wantSeed != got {
		t.Fatalf("want: '%d', got: '%d'", wantSeed, got)
	}
}

func prefixAndMT19937StreamEncrypt(knownPlaintext []byte) (ciphertext []byte, seed uint16) {
	n := testutil.MustRandomInt(32)
	prefix := testutil.MustRandomBytes(n)
	plaintext := append(prefix, bytes.Clone(knownPlaintext)...)
	seed = uint16(testutil.MustRandomInt(math.MaxUint16))
	ciphertext = PRNGStreamCrypt(plaintext, uint32(seed))
	return ciphertext, seed
}

func TestChallenge24_IdentifyTimeSeededMT19937Token(t *testing.T) {
	maxAge := 1000 * time.Second
	token := generatePasswordResetToken(maxAge)
	got := IsTokenTimeSeededMT19937Output(token, maxAge)

	if !got {
		t.Fatalf("want: '%v', got: '%v'", true, got)
	}
}

func generatePasswordResetToken(maxAge time.Duration) []byte {
	timeSeed := uint32(time.Now().Unix()) - uint32(testutil.MustRandomInt(int(maxAge.Seconds())+1))
	prng := rand.NewMT19937(timeSeed)
	token := make([]byte, 128)
	readMT19937Bytes(token, prng)
	return token
}
