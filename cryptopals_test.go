package cryptopals

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"os"
	"testing"

	"github.com/saclark/cryptopals-go/crypto"
	"github.com/saclark/cryptopals-go/crypto/analyze"
)

func TestChallenge1(t *testing.T) {
	input := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	want := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

	b, err := hex.DecodeString(input)
	if err != nil {
		t.Fatal(err)
	}

	got := base64.StdEncoding.EncodeToString(b)
	if want != got {
		t.Errorf("want: %s, got: %s", want, got)
	}
}

func TestChallenge2(t *testing.T) {
	inputA := "1c0111001f010100061a024b53535009181c"
	inputB := "686974207468652062756c6c277320657965"
	want := "746865206b696420646f6e277420706c6179"

	bytesA, err := hex.DecodeString(inputA)
	if err != nil {
		t.Fatal(err)
	}
	bytesB, err := hex.DecodeString(inputB)
	if err != nil {
		t.Fatal(err)
	}

	xoredBytes := crypto.FixedXOR(bytesA, bytesB)

	got := hex.EncodeToString(xoredBytes)
	if want != got {
		t.Errorf("want: %s, got: %s", want, got)
	}
}

func TestChallenge3(t *testing.T) {
	input := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	want := "Cooking MC's like a pound of bacon"

	b, err := hex.DecodeString(input)
	if err != nil {
		t.Fatal(err)
	}

	analyzer := analyze.SingleByteXORAnalyzer{}
	analyzer.AnalyzeBytes(b)

	result := analyzer.LeadingResult()
	got := string(result.PlainText)
	if want != got {
		t.Errorf("want: %s, got: %s", want, got)
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

	analyzer := analyze.SingleByteXORAnalyzer{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		b, err := hex.DecodeString(scanner.Text())
		if err != nil {
			t.Fatal(err)
		}
		analyzer.AnalyzeBytes(b)
	}

	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}

	result := analyzer.LeadingResult()
	got := string(result.PlainText)
	if want != got {
		t.Errorf("want: '%s', got: '%s'", want, got)
	}
}
