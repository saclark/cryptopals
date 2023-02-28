package xor

import (
	"bytes"
	"fmt"
	"math"
	"testing"
)

func roundToDecimalPlaces(f float64, scale int) float64 {
	s := float64(1)
	for i := 0; i < scale; i++ {
		s *= 10
	}
	return math.Round(f*s) / s
}

func TestRelEngLetterFreqs_SumToOne(t *testing.T) {
	var got float64
	for _, f := range relEngCharFreqs {
		got += f
	}
	if roundToDecimalPlaces(got, 7) != 1 {
		t.Errorf("want: %.7f, got: %.7f", 1.0, got)
	}
}

func TestScoreEnglishLikeness(t *testing.T) {
	tt := []struct {
		input []byte
		want  float64
	}{
		{[]byte("A"), 0.0651738},
		{[]byte("B"), 0.0124248},
		{[]byte("C"), 0.0217339},
		{[]byte("D"), 0.0349835},
		{[]byte("E"), 0.1041442},
		{[]byte("F"), 0.0197881},
		{[]byte("G"), 0.0158610},
		{[]byte("H"), 0.0492888},
		{[]byte("I"), 0.0558094},
		{[]byte("J"), 0.0009033},
		{[]byte("K"), 0.0050529},
		{[]byte("L"), 0.0331490},
		{[]byte("M"), 0.0202124},
		{[]byte("N"), 0.0564513},
		{[]byte("O"), 0.0596302},
		{[]byte("P"), 0.0137645},
		{[]byte("Q"), 0.0008606},
		{[]byte("R"), 0.0497563},
		{[]byte("S"), 0.0515760},
		{[]byte("T"), 0.0729357},
		{[]byte("U"), 0.0225134},
		{[]byte("V"), 0.0082903},
		{[]byte("W"), 0.0171272},
		{[]byte("X"), 0.0013692},
		{[]byte("Y"), 0.0145984},
		{[]byte("Z"), 0.0007836},
		{[]byte("a"), 0.0651738},
		{[]byte("b"), 0.0124248},
		{[]byte("c"), 0.0217339},
		{[]byte("d"), 0.0349835},
		{[]byte("e"), 0.1041442},
		{[]byte("f"), 0.0197881},
		{[]byte("g"), 0.0158610},
		{[]byte("h"), 0.0492888},
		{[]byte("i"), 0.0558094},
		{[]byte("j"), 0.0009033},
		{[]byte("k"), 0.0050529},
		{[]byte("l"), 0.0331490},
		{[]byte("m"), 0.0202124},
		{[]byte("n"), 0.0564513},
		{[]byte("o"), 0.0596302},
		{[]byte("p"), 0.0137645},
		{[]byte("q"), 0.0008606},
		{[]byte("r"), 0.0497563},
		{[]byte("s"), 0.0515760},
		{[]byte("t"), 0.0729357},
		{[]byte("u"), 0.0225134},
		{[]byte("v"), 0.0082903},
		{[]byte("w"), 0.0171272},
		{[]byte("x"), 0.0013692},
		{[]byte("y"), 0.0145984},
		{[]byte("z"), 0.0007836},
		{[]byte(" "), 0.1918182},
		{[]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ "), 0.0370370},
		{[]byte("abcdefghijklmnopqrstuvwxyz "), 0.0370370},
		{[]byte("THE QUICK BROWN FOX JUMPED OVER THE LAZY DOG!"), 0.0669323},
		{[]byte("the quick brown fox jumped over the lazy dog!"), 0.0669323},
		{[]byte("three"), 0.0760538},
	}

	for _, tc := range tt {
		t.Run(string(tc.input), func(t *testing.T) {
			if got := scoreEnglishLikeness(tc.input); roundToDecimalPlaces(got, 7) != tc.want {
				t.Errorf("want: %.7f, got: %.7f", tc.want, got)
			}
		})
	}

	// Verify non-letter and non-space chars do not contribute to the score.
	for i := 0; i < 256; i++ {
		if (i >= 'A' && i <= 'Z') || (i >= 'a' && i <= 'z') || i == ' ' {
			continue
		}
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			if got := scoreEnglishLikeness([]byte{byte(i)}); got != 0 {
				t.Errorf("want: %f, got: %f", 0.0, got)
			}
		})
	}
}

func TestScoreRepeatingKeySize(t *testing.T) {
	tt := []struct {
		ciphertext []byte
		keySize    int
		want       float64
	}{
		{[]byte("1234567890"), 1, 1.888889},
		{[]byte("1234567890"), 2, 1.75},
		{[]byte("123456789"), 3, 2.666667},
		{[]byte("12345678"), 4, 1.25},
		{[]byte("123456789012345"), 5, 2.6},

		// Score should be weighted to remove ciphertext length bias
		{[]byte("0111"), 2, 0.5},
		{[]byte("01110111"), 2, 0.5},
		{[]byte("0111011101110111"), 2, 0.5},
		{[]byte("01110111011101110111011101110111"), 2, 0.5},

		// Score should be weighted to remove key length bias
		{[]byte("00110011111111110010"), 2, 0.5},
		{[]byte("01011111010111110101"), 4, 0.5},
		{[]byte("10101010101111111111"), 10, 0.5},
	}

	for _, tc := range tt {
		t.Run(fmt.Sprintf("%s, %d", tc.ciphertext, tc.keySize), func(t *testing.T) {
			got := scoreRepeatingKeySize(tc.ciphertext, tc.keySize)
			if tc.want != roundToDecimalPlaces(got, 6) {
				t.Errorf("want: '%.6f', got: '%.6f'", tc.want, got)
			}
		})
	}
}

func TestHammingDistance(t *testing.T) {
	tt := []struct {
		a    []byte
		b    []byte
		want int
	}{
		{[]byte{}, []byte{}, 0},
		{[]byte("0"), []byte("0"), 0},
		{[]byte("0"), []byte("1"), 1},
		{[]byte("0000"), []byte("0000"), 0},
		{[]byte("0000"), []byte("1000"), 1},
		{[]byte("0000"), []byte("1100"), 2},
		{[]byte("0000"), []byte("1110"), 3},
		{[]byte("0000"), []byte("1111"), 4},
		{[]byte("this is a test"), []byte("this is a test"), 0},
		{[]byte("this is a test"), []byte("wokka wokka!!!"), 37},
	}

	for _, tc := range tt {
		t.Run(fmt.Sprintf("%s, %s", tc.a, tc.b), func(t *testing.T) {
			aBefore := make([]byte, len(tc.a))
			bBefore := make([]byte, len(tc.b))
			copy(aBefore, tc.a)
			copy(bBefore, tc.b)

			got := hammingDistance(tc.a, tc.b)
			if tc.want != got {
				t.Errorf("want: '%d', got: '%d'", tc.want, got)
			}
			if !bytes.Equal(aBefore, tc.a) {
				t.Errorf("original bytes altered: before: '%v', after: '%v'", aBefore, tc.a)
			}
			if !bytes.Equal(bBefore, tc.b) {
				t.Errorf("original bytes altered: before: '%v', after: '%v'", bBefore, tc.b)
			}
		})
	}
}

func TestTransposeBlocks(t *testing.T) {
	tt := []struct {
		s         []byte
		blockSize int
		want      [][]byte
	}{
		{[]byte{}, 2, [][]byte{}},
		{[]byte{0}, 1, [][]byte{{0}}},
		{[]byte{0}, 2, [][]byte{{0}}},
		{[]byte{0, 1, 2, 3}, 1, [][]byte{{0, 1, 2, 3}}},
		{[]byte{0, 1, 2, 3}, 2, [][]byte{{0, 2}, {1, 3}}},
		{[]byte{0, 1, 2, 3}, 3, [][]byte{{0, 3}, {1}, {2}}},
		{[]byte{0, 1, 2, 3}, 4, [][]byte{{0}, {1}, {2}, {3}}},
		{[]byte{0, 1, 2, 3}, 5, [][]byte{{0}, {1}, {2}, {3}}},
	}

	for _, tc := range tt {
		t.Run(fmt.Sprintf("%v, %d", tc.s, tc.blockSize), func(t *testing.T) {
			got := transposeBlocks(tc.s, tc.blockSize)
			if len(tc.want) != len(got) {
				t.Fatalf("want: '%v', got: '%v'", tc.want, got)
			}
			for i := range tc.want {
				if !bytes.Equal(tc.want[i], got[i]) {
					t.Fatalf("want: '%v', got: '%v'", tc.want, got)
				}
			}
		})
	}
}
