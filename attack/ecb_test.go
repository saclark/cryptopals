package attack

import (
	"encoding/hex"
	"math"
	"testing"
)

func TestDetectECBMode(t *testing.T) {
	tt := []struct {
		desc       string
		ciphertext []byte
		blockSize  int
		want       float64
	}{
		{
			desc:       "0 of 0 blocks duplicated",
			ciphertext: []byte(""),
			blockSize:  2,
			want:       0,
		},
		{
			desc:       "0 of 1 blocks duplicated",
			ciphertext: []byte("00"),
			blockSize:  2,
			want:       0,
		},
		{
			desc:       "0 of 4 blocks duplicated",
			ciphertext: []byte("00112233"),
			blockSize:  2,
			want:       0,
		},
		{
			desc:       "2 of 4 blocks duplicated",
			ciphertext: []byte("00001122"),
			blockSize:  2,
			want:       0.5,
		},
		{
			desc:       "3 of 4 blocks duplicated",
			ciphertext: []byte("00000011"),
			blockSize:  2,
			want:       0.75,
		},
		{
			desc:       "4 of 4 blocks duplicated - none distinct",
			ciphertext: []byte("00000000"),
			blockSize:  2,
			want:       1,
		},
		{
			desc:       "4 of 4 blocks duplicated - two distinct",
			ciphertext: []byte("00110011"),
			blockSize:  2,
			want:       1,
		},
		{
			desc:       "0 of 5 blocks duplicated",
			ciphertext: []byte("0011223344"),
			blockSize:  2,
			want:       0,
		},
		{
			desc:       "2 of 5 blocks duplicated",
			ciphertext: []byte("0000112233"),
			blockSize:  2,
			want:       0.4,
		},
		{
			desc:       "3 of 5 blocks duplicated",
			ciphertext: []byte("0000001122"),
			blockSize:  2,
			want:       0.6,
		},
		{
			desc:       "4 of 5 blocks duplicated - 2 distinct",
			ciphertext: []byte("0000000011"),
			blockSize:  2,
			want:       0.8,
		},
		{
			desc:       "4 of 5 blocks duplicated - 3 distinct",
			ciphertext: []byte("0011001122"),
			blockSize:  2,
			want:       0.8,
		},
		{
			desc:       "5 of 5 blocks duplicated",
			ciphertext: []byte("0011001100"),
			blockSize:  2,
			want:       1,
		},
	}

	for _, tc := range tt {
		t.Run(tc.desc, func(t *testing.T) {
			if got := DetectECBMode(tc.ciphertext, tc.blockSize); tc.want != roundToDecimalPlaces(got, 7) {
				t.Errorf("want: '%.7f', got: '%.7f'", tc.want, got)
			}
		})
	}
}

func roundToDecimalPlaces(f float64, scale int) float64 {
	s := float64(1)
	for i := 0; i < scale; i++ {
		s *= 10
	}
	return math.Round(f*s) / s
}

func hexMustDecodeString(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
