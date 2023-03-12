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
	var want bool
	updateWant := func(isECB bool) {
		want = isECB
	}

	encrypt, err := exploitable.NewModeDetectionOracle(updateWant)
	if err != nil {
		t.Fatalf("creating oracle: %v", err)
	}

	for i := 0; i < 10; i++ {
		got, err := exploit.IsOracleECBMode(aes.BlockSize, encrypt)
		if err != nil {
			t.Fatalf("detecting mode: %v", err)
		}

		if want != got {
			t.Errorf("want: '%v', got: '%v'", want, got)
		}
	}
}
