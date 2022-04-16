package xor

import (
	"bytes"
	"fmt"
	"math"
	"testing"
)

func TestScoreKeySize(t *testing.T) {
	testCases := []struct {
		ciphertext       []byte
		keySize          int
		blockComparisons int
		want             float64
	}{
		{[]byte("12345678910"), 1, 9, 1.777778},
		{[]byte("12345678910"), 2, 1, 1.5},
		{[]byte("12345678910"), 2, 2, 1.5},
		{[]byte("12345678910"), 2, 3, 1.666667},
		{[]byte("12345678910"), 2, 4, 1.875000},
		{[]byte("12345678910"), 3, 1, 2.333333},
		{[]byte("12345678910"), 3, 2, 2.666667},
		{[]byte("12345678910"), 4, 1, 1.250000},
		{[]byte("12345678910"), 5, 1, 2.400000},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%s, %d, %d", tc.ciphertext, tc.keySize, tc.blockComparisons), func(t *testing.T) {
			got := scoreKeySize(tc.ciphertext, tc.keySize, tc.blockComparisons)
			if tc.want != math.Round(got*1000000)/1000000 {
				t.Errorf("want: '%f', got: '%f'", tc.want, got)
			}
		})
	}
}

func TestHammingDistance(t *testing.T) {
	testCases := []struct {
		a    []byte
		b    []byte
		want int
	}{
		{[]byte{}, []byte{}, 0},
		{[]byte("this is a test"), []byte("this is a test"), 0},
		{[]byte{}, []byte("wokka wokka!!!"), 112},
		{[]byte("this is a test"), []byte{}, 112},
		{[]byte("this is a test"), []byte("wokka wokka!!!"), 37},
		{[]byte("this is a test"), []byte("wokka wokka!!!!!!"), 61},
		{[]byte("this is a test!!!"), []byte("wokka wokka!!!"), 61},
	}

	for _, tc := range testCases {
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
				t.Errorf("original bytes altered: before: '%s', after: '%s'", aBefore, tc.a)
			}
			if !bytes.Equal(bBefore, tc.b) {
				t.Errorf("original bytes altered: before: '%s', after: '%s'", bBefore, tc.b)
			}
		})
	}
}

func TestTransposeBlocks(t *testing.T) {
	testCases := []struct {
		s         []byte
		blockSize int
		want      [][]byte
	}{
		{[]byte{}, 2, [][]byte{}},
		{[]byte{0, 1, 2, 3}, 1, [][]byte{{0, 1, 2, 3}}},
		{[]byte{0, 1, 2, 3}, 2, [][]byte{{0, 2}, {1, 3}}},
		{[]byte{0, 1, 2, 3}, 3, [][]byte{{0, 3}, {1}, {2}}},
		{[]byte{0, 1, 2, 3}, 4, [][]byte{{0}, {1}, {2}, {3}}},
		{[]byte{0, 1, 2, 3}, 5, [][]byte{{0}, {1}, {2}, {3}}},
	}

	for _, tc := range testCases {
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
