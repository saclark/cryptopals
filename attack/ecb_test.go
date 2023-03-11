package attack

import (
	"crypto/aes"
	"encoding/hex"
	"fmt"
	"math"
	"testing"
)

func TestDetectECBMode(t *testing.T) {
	tt := []struct {
		ciphertext []byte
		want       float64
	}{
		{
			ciphertext: hexMustDecodeString(""),
			want:       0,
		},
		{
			ciphertext: hexMustDecodeString("e6393574e9270c4f885233cad8e87e8500efcba137118fcfdf1d268b0d6cfae17bacdbc9c06a0a0420db453b8b4335dc00efcba137118fcfdf1d268b0d6cfae1"),
			want:       0.25,
		},
		{
			ciphertext: hexMustDecodeString("e6393574e9270c4f885233cad8e87e8500efcba137118fcfdf1d268b0d6cfae1e6393574e9270c4f885233cad8e87e8500efcba137118fcfdf1d268b0d6cfae1"),
			want:       0.5,
		},
		{
			ciphertext: hexMustDecodeString("e6393574e9270c4f885233cad8e87e85e6393574e9270c4f885233cad8e87e85e6393574e9270c4f885233cad8e87e85e6393574e9270c4f885233cad8e87e85"),
			want:       0.75,
		},
		{
			ciphertext: hexMustDecodeString("5626f1d6a7a3ee12fdd59cc6448242fe"),
			want:       1.0,
		},
	}

	for _, tc := range tt {
		t.Run(fmt.Sprintf("%x", tc.ciphertext), func(t *testing.T) {
			if got := DetectECBMode(tc.ciphertext, aes.BlockSize); tc.want != roundToDecimalPlaces(got, 7) {
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
