package set2

import "testing"

// An ECB/CBC detection oracle
// See: https://www.cryptopals.com/sets/2/challenges/11
func TestChallenge11(t *testing.T) {
	var oracle ModeDetectionOracle
	for i := 0; i < 10; i++ {
		got, err := DetectECBModeOracle(oracle.Encrypt)
		if err != nil {
			t.Fatalf("err: %v", err)
		}

		want := oracle.IsECB
		if want != got {
			t.Errorf("want: '%v', got: '%v'", want, got)
		}
	}
}
