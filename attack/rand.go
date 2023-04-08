package attack

import "github.com/saclark/cryptopals/rand"

const (
	n    = 624
	u    = 11
	s, b = 7, 0x9d2c5680
	t, c = 15, 0xefc60000
	l    = 18
)

// CloneMT19937FromOutput takes 624 numbers consecutively output from a 32-bit
// MT19937 PRNG and returns a new MT19937 PRNG whose internal state is identical
// to the one that produced the given ouput. It panics if len(output) < 624.
func CloneMT19937FromOutput(output []uint32) *rand.MT19937 {
	if len(output) < n {
		panic("cryptopals-go/attack: insufficient output")
	}

	state := make([]uint32, n)
	for i, y := range output {
		y ^= y >> l
		y ^= (y << t) & c
		y ^= ((y << s) & b) & (0x7f << s)
		y ^= ((y << s) & b) & (0x7f << (s * 2))
		y ^= ((y << s) & b) & (0x7f << (s * 3))
		y ^= ((y << s) & b) & ((0x7f << (s * 4)) & 0xffffffff)
		y ^= (y >> u)
		y ^= (y >> (u * 2))
		state[i] = y
	}

	return rand.NewMT19937FromState(state)
}
