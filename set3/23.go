// # Clone an MT19937 RNG from its output
//
// The internal state of MT19937 consists of 624 32 bit integers.
//
// For each batch of 624 outputs, MT permutes that internal state. By permuting
// state regularly, MT19937 achieves a period of 2**19937, which is Big.
//
// Each time MT19937 is tapped, an element of its internal state is subjected to
// a tempering function that diffuses bits through the result.
//
// The tempering function is invertible; you can write an "untemper" function
// that takes an MT19937 output and transforms it back into the corresponding
// element of the MT19937 state array.
//
// To invert the temper transform, apply the inverse of each of the operations
// in the temper transform in reverse order. There are two kinds of operations
// in the temper transform each applied twice; one is an XOR against a
// right-shifted value, and the other is an XOR against a left-shifted value
// AND'd with a magic number. So you'll need code to invert the "right" and the
// "left" operation.
//
// Once you have "untemper" working, create a new MT19937 generator, tap it for
// 624 outputs, untemper each of them to recreate the state of the generator,
// and splice that state into a new instance of the MT19937 generator.
//
// The new "spliced" generator should predict the values of the original.
//
// > # Stop and think for a second.
// > How would you modify MT19937 to make this attack hard? What would happen if
// > you subjected each tempered output to a cryptographic hash?

package set3

import (
	"github.com/saclark/cryptopals-go/attack"
	"github.com/saclark/cryptopals-go/rand"
)

// For the sake of this explanation, we'll use the following notation:
//
//	y       = The tempered value
//	y'      = The un-tempered value
//	a-z,A-F = A bit of the tempered value
//	_       = An unknown bit of the un-tempered value
//	.       = A 0 bit
//	1       = A 1 bit
//	a[i]    = The i'th bit of a, 0 being the most significant bit
//	a[i:j]  = The bits of a in range [i, j), 0 being the most significant bit
//
// First, we we need to invert:
//
//	y' = y ^ (y >> l)
//
// So let's see what that actually looks like:
//
//	abcdefghijklmnopqrstuvwxyzABCDEF = y
//	..................abcdefghijklmn = y >> l = y >> 18
//	abcdefghijklmnopqrstuvwxyzABCDEF = y
//	abcdefghijklmnopqr______________ = y' = y ^ (y >> l)
//
// We notice that:
//
//	y'[:18] = y[:18]
//	y'[18:] = y[:14] ^ y[18:]
//
// Therfore, we see that we can obtain y from y' via:
//
//	y[:18] = y'[:18]
//	y[18:] = y'[18:] ^ y[:14] = y'[18:] ^ y'[:14]
//
// Which, as it turns out, means we can simply re-apply the same tempering step
// to recover y:
//
//	y = y' ^ (y' >> l)
//
// We can demonstrate this:
//
//	abcdefghijklmnopqr______________ = y'
//	..................abcdefghijklmn = y' >> l = y' >> 18
//	abcdefghijklmnopqr______________ = y'
//	abcdefghijklmnopqrstuvwxyzABCDEF = y = y' ^ (y' >> l)
//
// Next, we need to invert:
//
//	y' = y ^ ((y << t) & c)
//
// Again, we'll write it out:
//
//	abcdefghijklmnopqrstuvwxyzABCDEF = y
//	pqrstuvwxyzABCDEF............... = y << t = y << 15
//	111.111111...11................. = c = 0xefc60000
//	pqr.tuvwxy...CD................. = (y << t) & c
//	abcdefghijklmnopqrstuvwxyzABCDEF = y
//	___d______klm__pqrstuvwxyzABCDEF = y' = y ^ ((y << t) & c)
//
// We notice that:
//
//	y'[15:] = y[15:]
//	y'[:15] = (y[15:29] & c) ^ y[:15]
//
// Therefore, we see that we can obtain y from y' via:
//
//	y[15:] = y'[15:]
//	y[:15] = y'[:15] ^ (y[15:29] & c) = y'[:15] ^ (y'[15:29] & c)
//
// And lucky for us, we may notice that because bits c[15:] are all 0, we can
// once again simply re-apply the same tempering step to obtain y:
//
//	y = y' ^ ((y' << t) & c)
//
// Which we can demonstrate:
//
//	___d______klm__pqrstuvwxyzABCDEF = y'
//	pqrstuvwxyzABCDEF............... = y' << t = y' << 15
//	111.111111...11................. = c = 0xefc60000
//	pqr.tuvwxy...CD................. = (y' << t) & c
//	___d______klm__pqrstuvwxyzABCDEF = y'
//	abcdefghijklmnopqrstuvwxyzABCDEF = y = y' ^ ((y' << t) & c)
//
// Next, we need to invert:
//
//	y' = y ^ ((y << s) & b)
//
// Which looks like:
//
//	abcdefghijklmnopqrstuvwxyzABCDEF = y
//	hijklmnopqrstuvwxyzABCDEF....... = y << s = y << 7
//	1..111.1..1.11...1.1.11.1....... = b = 0x9d2c5680
//	h..klm.o..r.tu...y.A.CD.F....... = (y << s) & b
//	abcdefghijklmnopqrstuvwxyzABCDEF = y
//	_bc___g_ij_l__opq_s_u__x_zABCDEF = y' = y ^ ((y << s) & b)
//	_ij_l__opq_s_u__x_.A.CD.F....... = (y' << s) & b = (y' << 7) & b
//
// We notice that:
//
//	y'[25:] = y[25:]
//	y'[:25] = (y[7:] & b) ^ y[:25]
//
// If we try the same approach as the last two steps, by re-applying the
// corresponding tempering step, we won't get all of the original y bits back
// like we did in the first two steps. However, it does get us back bits y[18:]
// and if we have those, we can re-apply the same logic yet again to get the
// next 7 bits even higher than those. In fact, we could keep doing this until
// we have un-tempered all of the bits! But not quite. The problem is that when
// we first re-applied the original tempering step, we recovered bits y[18:] but
// also clobbered bits y[:18]. So what we need to do is with each application of
// (y' << s) & b in each iteration, isolate, via a mask, just the 7 bits we want
// to target, leaving the rest of the bits of y' unchanged. We can do this by
// ANDing (y' << s) & b with 7 consecutive 1-bits (0x7f), shifted left just the
// right amount to overlap our target bits for each iteration. This means that
// our un-tempering step will look like the following (we won't bother to fully
// write out/demonstrate what this looks like as it would be quite long).
//
//	y = y' ^ (((y' << s) & b) & (0x7f << s))
//	y = y' ^ (((y' << s) & b) & (0x7f << (s * 2)))
//	y = y' ^ (((y' << s) & b) & (0x7f << (s * 3)))
//	y = y' ^ (((y' << s) & b) & (0x7f << (s * 4)))
//
// Finally, we need to invert:
//
//	y' = y ^ ((y >> u) & d)
//
// Which looks like:
//
//	abcdefghijklmnopqrstuvwxyzABCDEF = y
//	...........abcdefghijklmnopqrstu = y >> u = y >> 11
//	11111111111111111111111111111111 = d = 0xffffffff
//	...........abcdefghijklmnopqrstu = (y >> u) & d
//	abcdefghijklmnopqrstuvwxyzABCDEF = y
//	abcdefghijk_____________________ = y' = y ^ ((y >> u) & d)
//
// And we see that:
//
//	y'[:11] = y[:11]
//	y'[11:] = y[:21] ^ y[11:]
//
// But knowing what we've learned from the previous steps and knowing that we
// already have bits y[:11] in y'[:11], let's rewrite this, breaking things up
// into 11 bit segments (except the last segment which only leaves 10 remaining
// bits). We get:
//
//	y'[:11] = y[:11]
//	y'[11:22] = y[:11] ^ y[11:22]
//	y'[22:] = y[11:21] ^ y[22:]
//
// Now, we can apply a little bit of algebra to show that:
//
//	y[:11] = y'[:11]
//	y[11:22] = y[:11] ^ y'[11:22] = y'[:11] ^ y'[11:22]
//	y[22:] = y[11:21] ^ y'[22:] = y'[:11] ^ y'[11:22] ^ y'[22:]
//
// Therefore, we just need to yet again re-apply the tempering step, but do it
// in two iterations, shifting right y' an additional u bits more on the second
// iteration:
//
//	y = y' ^ (y' >> u)
//	y = y' ^ (y' >> (u * 2))
//
// And with that, we've "un-tempered" a single element of the MT19937 state. Do
// this for 624 ints consecutively output from an MT19937 PRNG and we can
// determine it's internal state, allowing us to predict it's output.
func CloneMT19937FromOutput(output []uint32) *rand.MT19937 {
	return attack.CloneMT19937FromOutput(output)
}
