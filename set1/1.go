// # Convert hex to base64
//
// The string:
//
//	49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
//
// Should produce:
//
//	SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
//
// So go ahead and make that happen. You'll need to use this code for the rest
// of the exercises.
//
// > # Cryptopals Rule:
// > Always operate on raw bytes, never on encoded strings. Only use hex and
// > base64 for pretty-printing.

package set1

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

func ConvertHexToBase64(hexStr string) (string, error) {
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return "", fmt.Errorf("hex decoding string: %v", err)
	}
	return base64.StdEncoding.EncodeToString(b), nil
}
