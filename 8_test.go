package cryptopals

import (
	"bufio"
	"os"
	"testing"

	"github.com/saclark/cryptopals-go/aes"
	"github.com/saclark/cryptopals-go/exploit"
)

// Detect AES in ECB mode
// See: https://www.cryptopals.com/sets/1/challenges/8
func TestChallenge8(t *testing.T) {
	inputFile := "data/8.txt"
	want := "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a"

	file, err := os.Open(inputFile)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	var got string
	var maxScore float64
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		hexstr := scanner.Text()
		line := hexMustDecodeString(hexstr)
		s := exploit.DetectECBMode(line, aes.BlockSize)
		if s > maxScore {
			got = hexstr
			maxScore = s
		}
	}

	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}

	if want != got {
		t.Errorf("want: '%s', got: '%s'", want, got)
	}
}
