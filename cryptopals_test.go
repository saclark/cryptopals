package cryptopals

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"io/ioutil"
	"os"
	"testing"

	"github.com/saclark/cryptopals-go/xor"
)

func hexMustDecodeString(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func base64MustDecodeString(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestChallenge1(t *testing.T) {
	input := hexMustDecodeString("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
	want := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

	got := base64.StdEncoding.EncodeToString(input)
	if want != got {
		t.Errorf("want: '%s', got: '%s'", want, got)
	}
}

func TestChallenge2(t *testing.T) {
	inputA := hexMustDecodeString("1c0111001f010100061a024b53535009181c")
	inputB := hexMustDecodeString("686974207468652062756c6c277320657965")
	want := "746865206b696420646f6e277420706c6179"

	xoredBytes := xor.FixedXOR(inputA, inputB)

	got := hex.EncodeToString(xoredBytes)
	if want != got {
		t.Errorf("want: '%s', got: '%s'", want, got)
	}
}

func TestChallenge3(t *testing.T) {
	input := hexMustDecodeString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	want := "Cooking MC's like a pound of bacon"

	key, _ := xor.DetectRepeatingByteXORKey(input)
	plaintext := xor.RepeatingByteXOR(input, key)

	got := string(plaintext)
	if want != got {
		t.Errorf("want: '%s', got: '%s'", want, got)
	}
}

func TestChallenge4(t *testing.T) {
	inputFile := "challenge-data/4.txt"
	want := "Now that the party is jumping\n"

	file, err := os.Open(inputFile)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	var score float64
	var plaintext []byte
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := hexMustDecodeString(scanner.Text())
		key, s := xor.DetectRepeatingByteXORKey(line)
		if s >= score {
			score = s
			plaintext = xor.RepeatingByteXOR(line, key)
		}
	}

	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}

	got := string(plaintext)
	if want != got {
		t.Errorf("want: '%s', got: '%s'", want, got)
	}
}

func TestChallenge5(t *testing.T) {
	input := []byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
	key := []byte("ICE")
	want := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

	encrypted := xor.RepeatingXOR(input, key)

	got := hex.EncodeToString(encrypted)
	if want != got {
		t.Errorf("\nwant: '%s'\ngot : '%s'", want, got)
	}
}

func TestChallenge6(t *testing.T) {
	inputFile := "challenge-data/6.txt"
	want := "Terminator X: Bring the noise"

	b, err := ioutil.ReadFile(inputFile)
	if err != nil {
		t.Fatal(err)
	}
	b = base64MustDecodeString(string(b))

	key, _ := xor.DetectRepeatingXORKey(b, 2, 40, 12)

	// err = os.WriteFile("6_decoded.txt", xor.RepeatingXOR(b, key), 0644)
	// if err != nil {
	// 	t.Fatal(err)
	// }

	got := string(key)
	if want != got {
		t.Errorf("want: '%s', got: '%s'", want, got)
	}
}
