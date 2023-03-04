package aes

import (
	"bytes"
	"fmt"
	"math"
	"testing"
)

func TestEncryptThenDecryptECB(t *testing.T) {
	tt := []struct {
		plaintext  []byte
		key        []byte
		ciphertext []byte
	}{
		{
			plaintext:  []byte("YELLOW SUBMARINE"),
			key:        []byte("0123456789012345"),
			ciphertext: hexMustDecodeString("5626f1d6a7a3ee12fdd59cc6448242fe"),
		},
		{
			plaintext:  []byte("0000000000000000111111111111111100000000000000001111111111111111"),
			key:        []byte("0123456789012345"),
			ciphertext: hexMustDecodeString("e6393574e9270c4f885233cad8e87e8500efcba137118fcfdf1d268b0d6cfae1e6393574e9270c4f885233cad8e87e8500efcba137118fcfdf1d268b0d6cfae1"),
		},
	}

	for _, tc := range tt {
		t.Run(fmt.Sprintf("%v,%v", tc.plaintext, tc.key), func(t *testing.T) {
			encrypted, err := EncryptECB(tc.plaintext, tc.key)
			if err != nil {
				t.Fatalf("err encrypting: %v", err)
			}
			if !bytes.Equal(tc.ciphertext, encrypted) {
				t.Fatalf("want encrypted bytes: '%x', got encrypted bytes: '%x'", tc.ciphertext, encrypted)
			}

			decrypted, err := DecryptECB(encrypted, tc.key)
			if err != nil {
				t.Fatalf("err decrypting: %v", err)
			}
			if !bytes.Equal(tc.plaintext, decrypted) {
				t.Fatalf("want decrypted bytes: '%x', got decrypted bytes: '%x'", tc.plaintext, decrypted)
			}
		})
	}
}

func TestDetectECB(t *testing.T) {
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
			if got := DetectECB(tc.ciphertext); tc.want != roundToDecimalPlaces(got, 7) {
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
