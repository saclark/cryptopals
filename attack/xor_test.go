package attack

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/saclark/cryptopals-go/xor"
)

func TestDetectRepeatingByteXORKey_CorrectlyDetectsTheKey(t *testing.T) {
	plaintext := []byte("Yo, microphone check one, two, what is this?")
	ciphertext := make([]byte, len(plaintext))
	wantScore := 6.8653875
	for i := 0; i < 256; i++ {
		b := byte(i)
		xor.BytesRepeatingByte(ciphertext, plaintext, b)

		key, score := DetectRepeatingByteXORKey(ciphertext)
		if b != key {
			t.Fatalf("want: %x, got: %x", b, key)
		}
		if wantScore != roundToDecimalPlaces(score, 7) {
			t.Fatalf("want: %.7f, got: %.7f", wantScore, score)
		}
	}
}

func TestDetectRepeatingByteXORKey_CorrectlyScoresTheDetectedKey(t *testing.T) {
	tt := []struct {
		plaintext []byte
		score     float64
	}{
		{[]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ "), 3.7037037},
		{[]byte("abcdefghijklmnopqrstuvwxyz "), 3.7037037},
		{[]byte("ThE qUiCk BrOwN fOx JuMpEd OvEr ThE lAzY dOg!"), 6.6932273},
		{[]byte("ThE, qUiCk. BrOwN; fOx? JuMpEd' OvEr( ThE$ lAzY] dOg!"), 5.6829289},
	}

	b := byte('X')
	for _, tc := range tt {
		t.Run(string(tc.plaintext), func(t *testing.T) {
			ciphertext := make([]byte, len(tc.plaintext))
			xor.BytesRepeatingByte(ciphertext, tc.plaintext, b)
			key, score := DetectRepeatingByteXORKey(ciphertext)
			if b != key {
				t.Errorf("want: %x, got: %x", b, key)
			}
			if tc.score != roundToDecimalPlaces(score, 7) {
				t.Errorf("want: %.7f, got: %.7f", tc.score, score)
			}
		})
	}
}

func TestDetectRepeatingXORKey_CorrectlyDetectsTheKey(t *testing.T) {
	plaintext := []byte("Yo, microphone check one, two, what is this?")
	wantKey := []byte("abc")
	ciphertext := make([]byte, len(plaintext))
	wantScore := 5.3456014

	xor.BytesRepeating(ciphertext, plaintext, wantKey)

	key, score := DetectRepeatingXORKey(ciphertext, 1, 5)
	if bytes.Equal(wantKey, key) {
		t.Fatalf("want: %x, got: %x", wantKey, key)
	}
	if wantScore != roundToDecimalPlaces(score, 7) {
		t.Fatalf("want: %.7f, got: %.7f", wantScore, score)
	}
}

func TestRelEngLetterFreqs_SumToOne(t *testing.T) {
	const want = 1.0
	var got float64
	for _, f := range relEngCharFreqs {
		got += f
	}
	if roundToDecimalPlaces(got, 7) != want {
		t.Errorf("want: %.7f, got: %.7f", want, got)
	}
}

func TestScoreEnglishLikeness(t *testing.T) {
	tt := []struct {
		input []byte
		want  float64
	}{
		{[]byte("A"), 6.51738},
		{[]byte("B"), 1.24248},
		{[]byte("C"), 2.17339},
		{[]byte("D"), 3.49835},
		{[]byte("E"), 10.41442},
		{[]byte("F"), 1.97881},
		{[]byte("G"), 1.58610},
		{[]byte("H"), 4.92888},
		{[]byte("I"), 5.58094},
		{[]byte("J"), 0.09033},
		{[]byte("K"), 0.50529},
		{[]byte("L"), 3.31490},
		{[]byte("M"), 2.02124},
		{[]byte("N"), 5.64513},
		{[]byte("O"), 5.96302},
		{[]byte("P"), 1.37645},
		{[]byte("Q"), 0.08606},
		{[]byte("R"), 4.97563},
		{[]byte("S"), 5.15760},
		{[]byte("T"), 7.29357},
		{[]byte("U"), 2.25134},
		{[]byte("V"), 0.82903},
		{[]byte("W"), 1.71272},
		{[]byte("X"), 0.13692},
		{[]byte("Y"), 1.45984},
		{[]byte("Z"), 0.07836},
		{[]byte("a"), 6.51738},
		{[]byte("b"), 1.24248},
		{[]byte("c"), 2.17339},
		{[]byte("d"), 3.49835},
		{[]byte("e"), 10.41442},
		{[]byte("f"), 1.97881},
		{[]byte("g"), 1.58610},
		{[]byte("h"), 4.92888},
		{[]byte("i"), 5.58094},
		{[]byte("j"), 0.09033},
		{[]byte("k"), 0.50529},
		{[]byte("l"), 3.31490},
		{[]byte("m"), 2.02124},
		{[]byte("n"), 5.64513},
		{[]byte("o"), 5.96302},
		{[]byte("p"), 1.37645},
		{[]byte("q"), 0.08606},
		{[]byte("r"), 4.97563},
		{[]byte("s"), 5.15760},
		{[]byte("t"), 7.29357},
		{[]byte("u"), 2.25134},
		{[]byte("v"), 0.82903},
		{[]byte("w"), 1.71272},
		{[]byte("x"), 0.13692},
		{[]byte("y"), 1.45984},
		{[]byte("z"), 0.07836},
		{[]byte(" "), 19.18182},
		{[]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ "), 3.7037037},
		{[]byte("abcdefghijklmnopqrstuvwxyz "), 3.7037037},
		{[]byte("THE QUICK BROWN FOX JUMPED OVER THE LAZY DOG!"), 6.6932273},
		{[]byte("the quick brown fox jumped over the lazy dog!"), 6.6932273},
		{[]byte("three"), 7.6053840},
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

func TestScoreRepeatingXORKeySize(t *testing.T) {
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
			got := scoreRepeatingXORKeySize(tc.ciphertext, tc.keySize)
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
