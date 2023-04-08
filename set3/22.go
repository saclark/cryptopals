// # Crack an MT19937 seed
//
// Make sure your MT19937 accepts an integer seed value. Test it (verify that
// you're getting the same sequence of outputs given a seed).
//
// Write a routine that performs the following operation:
//
// * Wait a random number of seconds between, I don't know, 40 and 1000.
// * Seeds the RNG with the current Unix timestamp
// * Waits a random number of seconds again.
// * Returns the first 32 bit output of the RNG.
//
// You get the idea. Go get coffee while it runs. Or just simulate the passage
// of time, although you're missing some of the fun of this exercise if you do
// that.
//
// From the 32 bit RNG output, discover the seed.

package set3

import (
	"fmt"
	"time"

	"github.com/saclark/cryptopals/rand"
)

func RecoverPRNGSeed(prngOutput, maxElapsedSecs uint32) (uint32, error) {
	prng := new(rand.MT19937)
	now := uint32(time.Now().Unix())
	t := now - maxElapsedSecs - 5 // 5 seconds of margin
	for ; t <= now; t++ {
		prng.Seed(t)
		if prng.Uint32() == prngOutput {
			return t, nil
		}
	}
	return 0, fmt.Errorf("unable to recover PRNG seed")
}
