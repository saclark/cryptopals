package cryptopals

import (
	"testing"

	"github.com/saclark/cryptopals-go/aes"
	"github.com/saclark/cryptopals-go/attack"
	"github.com/saclark/cryptopals-go/oracle"
)

// An ECB/CBC detection oracle
// See: https://www.cryptopals.com/sets/2/challenges/11
func TestChallenge11(t *testing.T) {
	encrypt, want, err := oracle.NewModeDetectionOracle()
	if err != nil {
		t.Fatalf("creating oracle: %v", err)
	}

	isECB, err := attack.IsECBMode(aes.BlockSize, encrypt)
	if err != nil {
		t.Fatalf("detecting mode: %v", err)
	}

	got := oracle.ModeECB
	if !isECB {
		got = oracle.ModeCBC
	}

	if want != got {
		t.Errorf("want: '%v', got: '%v'", want, got)
	}
}
