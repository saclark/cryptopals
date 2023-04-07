package rand

const (
	f          = 1812433253
	w, n, m, r = 32, 624, 397, 31
	a          = 0x9908b0df
	u, d       = 11, 0xffffffff
	s, b       = 7, 0x9d2c5680
	t, c       = 15, 0xefc60000
	l          = 18
	lowerMask  = (1 << r) - 1
	upperMask  = (^lowerMask) & d
)

// MT19937 implements the standard 32-bit MT19937 Mersenne Twister.
type MT19937 struct {
	index uint32
	state []uint32
}

// NewMT19937 returns a 32-bit MT19937 Mersenne Twister, seeded with seed.
func NewMT19937(seed uint32) *MT19937 {
	mt := &MT19937{}
	mt.Seed(seed)
	return mt
}

// NewMT19937FromState returns a 32-bit MT19937 Mersenne Twister with the given
// internal state. It panics if len(output) < 624.
func NewMT19937FromState(state []uint32) *MT19937 {
	if len(state) < n {
		panic("cryptopals-go/rand: insufficient state")
	}
	return &MT19937{
		index: n,
		state: state,
	}
}

// Seed seeds, or re-seeds, the generator.
func (mt *MT19937) Seed(seed uint32) {
	mt.index = n
	mt.state = make([]uint32, n)
	mt.state[0] = seed
	for i := uint32(1); i < n; i++ {
		mt.state[i] = (f*(mt.state[i-1]^(mt.state[i-1]>>(w-2))) + i) & d
	}
}

// Uint32 returns a random uint32. It panics if the generator has not been
// seeded.
func (mt *MT19937) Uint32() uint32 {
	if mt.state == nil {
		panic("cryptopals-go/rand: generator not seeded")
	}
	if mt.index >= n {
		mt.twist()
	}

	y := mt.state[mt.index]
	y ^= (y >> u) & d
	y ^= (y << s) & b
	y ^= (y << t) & c
	y ^= y >> l

	mt.index++
	return y & d
}

func (mt *MT19937) twist() {
	for i := 0; i < n; i++ {
		x := (mt.state[i] & upperMask) | (mt.state[(i+1)%n] & lowerMask)
		xA := x >> 1
		if (x % 2) != 0 {
			xA = xA ^ a
		}
		mt.state[i] = mt.state[(i+m)%n] ^ xA
	}
	mt.index = 0
}
