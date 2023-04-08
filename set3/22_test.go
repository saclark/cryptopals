package set3

import (
	"testing"
	"time"

	"github.com/saclark/cryptopals/internal/testutil"
	"github.com/saclark/cryptopals/rand"
)

func TestChallenge22(t *testing.T) {
	const maxElapsedSecs = 1000
	want := uint32(time.Now().Unix()) - uint32(testutil.MustRandomInt(maxElapsedSecs+1))
	prng := rand.NewMT19937(want)

	got, err := RecoverPRNGSeed(prng.Uint32(), maxElapsedSecs)
	if err != nil {
		t.Fatalf("recovering PRNG seed: %v", err)
	}

	if want != got {
		t.Errorf("want: %d, got: %d", want, got)
	}
}
