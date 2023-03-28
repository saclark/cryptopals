// # Implement the MT19937 Mersenne Twister RNG
//
// You can get the psuedocode for this from Wikipedia.
//
// If you're writing in Python, Ruby, or (gah) PHP, your language is probably
// already giving you MT19937 as "rand()"; *don't use rand()*. Write the RNG
// yourself.

package set3

import "github.com/saclark/cryptopals-go/rand"

func NewMT19937PRNG(seed uint32) *rand.MT19937 {
	return rand.NewMT19937(seed)
}
