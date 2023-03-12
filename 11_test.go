package cryptopals

import (
	"testing"

	"github.com/saclark/cryptopals-go/aes"
	"github.com/saclark/cryptopals-go/exploit"
	"github.com/saclark/cryptopals-go/exploitable"
)

// An ECB/CBC detection oracle
// See: https://www.cryptopals.com/sets/2/challenges/11
func TestChallenge11(t *testing.T) {
	encrypt, want, err := exploitable.NewModeDetectionOracle()
	if err != nil {
		t.Fatalf("creating oracle: %v", err)
	}

	isECB, err := exploit.IsECBMode(aes.BlockSize, encrypt)
	if err != nil {
		t.Fatalf("detecting mode: %v", err)
	}

	got := exploitable.ModeECB
	if !isECB {
		got = exploitable.ModeCBC
	}

	if want != got {
		t.Errorf("want: '%v', got: '%v'", want, got)
	}
}
