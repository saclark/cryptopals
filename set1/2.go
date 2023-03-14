// # Fixed XOR
//
// Write a function that takes two equal-length buffers and produces their XOR
// combination.
//
// If your function works properly, then when you feed it the string:
//
//	1c0111001f010100061a024b53535009181c
//
// ... after hex decoding, and when XOR'd against:
//
//	686974207468652062756c6c277320657965
//
// ... should produce:
//
//	746865206b696420646f6e277420706c6179

package set1

import "github.com/saclark/cryptopals-go/xor"

func FixedXOR(x, y []byte) []byte {
	xoredBytes := make([]byte, len(x))
	xor.BytesFixed(xoredBytes, x, y)
	return xoredBytes
}
