package xor

import (
	"bytes"
	"fmt"
	"math"
	"testing"
)

func TestScoreEnglishLikeness(t *testing.T) {
	tt := []struct {
		input []byte
		want  float64
	}{
		{[]byte(" "), 3},
		{[]byte("abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ"), float64(55)},
	}

	for _, tc := range tt {
		t.Run(string(tc.input), func(t *testing.T) {
			if got := scoreEnglishLikeness(tc.input); got != tc.want {
				t.Errorf("want: %f, got :%f", tc.want, got)
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
			if tc.want != math.Round(got*1000000)/1000000 {
				t.Errorf("want: '%f', got: '%f'", tc.want, got)
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
