package set3

import (
	"testing"
)

func TestChallenge21(t *testing.T) {
	wantNums := []uint32{
		1649682285,
		1729432552,
		971315765,
		601447217,
		712770472,
		4145654589,
		3125280396,
		2415329191,
		1027632896,
		3653043045,
		2639294067,
		2811568043,
		1709849184,
		710011471,
		3420162221,
		3264220789,
		744927563,
		569543011,
		1906780862,
		605372253,
	}

	prng := NewMT19937PRNG(1988)

	for i, want := range wantNums {
		got := prng.Uint32()
		if want != got {
			t.Fatalf("%d: want: %d, got: %d", i, want, got)
		}
	}
}
