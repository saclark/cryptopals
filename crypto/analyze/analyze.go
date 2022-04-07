package analyze

import (
	"math"
	"strings"

	"github.com/saclark/cryptopals-go/crypto"
)

var charFrequencies = map[rune]float64{
	' ': 15, // I made up this score.
	'E': 12.02,
	'T': 9.10,
	'A': 8.12,
	'O': 7.68,
	'I': 7.31,
	'N': 6.95,
	'S': 6.28,
	'R': 6.02,
	'H': 5.92,
	'D': 4.32,
	'L': 3.98,
	'U': 2.88,
	'C': 2.71,
	'M': 2.61,
	'F': 2.30,
	'Y': 2.11,
	'W': 2.09,
	'G': 2.03,
	'P': 1.82,
	'B': 1.49,
	'V': 1.11,
	'K': 0.69,
	'X': 0.17,
	'Q': 0.11,
	'J': 0.10,
	'Z': 0.07,
}

type SingleByteXORAnalyzer struct {
	result *SingleByteXORAnalyzerResult
}

type SingleByteXORAnalyzerResult struct {
	CipherText []byte
	PlainText  []byte
	Key        byte
	Score      float64
}

func (a *SingleByteXORAnalyzer) AnalyzeBytes(cipherText []byte) {
	for k := 0; k <= math.MaxUint8; k++ {
		xoredBytes := crypto.SingleByteXOR(cipherText, uint8(k))
		text := string(xoredBytes)
		score := englishLikenessScore(text)
		if a.result == nil || score > a.result.Score {
			a.result = &SingleByteXORAnalyzerResult{
				CipherText: cipherText,
				PlainText:  xoredBytes,
				Key:        byte(k),
				Score:      score,
			}
		}
	}
}

func (a *SingleByteXORAnalyzer) LeadingResult() *SingleByteXORAnalyzerResult {
	return a.result
}

func englishLikenessScore(text string) float64 {
	text = strings.ToUpper(text)
	var score float64
	for _, r := range text {
		n, found := charFrequencies[r]
		if found {
			score += n
		}
	}
	return score
}
