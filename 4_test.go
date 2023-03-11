package cryptopals

import (
	"bufio"
	"os"
	"testing"

	"github.com/saclark/cryptopals-go/attack"
	"github.com/saclark/cryptopals-go/xor"
)

// Detect single-character XOR
// See: https://www.cryptopals.com/sets/1/challenges/4
func TestChallenge4(t *testing.T) {
	inputFile := "data/4.txt"
	want := "Now that the party is jumping\n"

	file, err := os.Open(inputFile)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	var maxScore float64
	var plaintext []byte
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := hexMustDecodeString(scanner.Text())
		key, s := attack.DetectRepeatingByteXORKey(line)
		if s >= maxScore {
			maxScore = s
			plaintext = make([]byte, len(line))
			xor.BytesRepeatingByte(plaintext, line, key)
		}
	}

	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}

	got := string(plaintext)
	if want != got {
		t.Errorf("want: '%x', got: '%x'", want, got)
	}
}
