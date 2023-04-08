package set3

import (
	"testing"

	"github.com/saclark/cryptopals/rand"
)

func TestChallenge23(t *testing.T) {
	prng := rand.NewMT19937(1988)

	output := make([]uint32, 624)
	for i := uint32(0); i < 624; i++ {
		output[i] = prng.Uint32()
	}

	clone := CloneMT19937FromOutput(output)
	for i := uint32(0); i < 624; i++ {
		if want, got := prng.Uint32(), clone.Uint32(); want != got {
			t.Fatalf("i = %d: want: %d, got: %d", i, want, got)
		}
	}
}
