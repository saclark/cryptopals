package pkcs7

import (
	"bytes"
	"fmt"
	"testing"
)

var validPaddingTestTable = []struct {
	blockSize int
	unpadded  []byte
	padded    []byte
}{
	{4, []byte{}, []byte("\x04\x04\x04\x04")},
	{4, []byte("0"), []byte("0\x03\x03\x03")},
	{4, []byte("00"), []byte("00\x02\x02")},
	{4, []byte("000"), []byte("000\x01")},
	{4, []byte("0000"), []byte("0000\x04\x04\x04\x04")},
	{4, []byte("00000"), []byte("00000\x03\x03\x03")},
	{4, []byte("000000"), []byte("000000\x02\x02")},
	{4, []byte("0000000"), []byte("0000000\x01")},
	{4, []byte("00000000"), []byte("00000000\x04\x04\x04\x04")},
	{4, []byte("00000\x02"), []byte("00000\x02\x02\x02")},
	{1, []byte("0"), []byte("0\x01")},
	{1, []byte("0\x01"), []byte("0\x01\x01")},
	{1, []byte{}, []byte("\x01")},
	{255, []byte{}, []byte("\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff")},
}

func TestPadThenUnpad(t *testing.T) {
	for _, tc := range validPaddingTestTable {
		t.Run(fmt.Sprintf("%v,%d", tc.unpadded, tc.blockSize), func(t *testing.T) {
			got := Pad(tc.unpadded, tc.blockSize)
			if !bytes.Equal(tc.padded, got) {
				t.Errorf("want padded bytes: '%v', got padded bytes: '%v'", tc.padded, got)
			}
			if got, ok := Unpad(got, tc.blockSize); !ok {
				t.Errorf("want: Unpad ok: %v, got: Unpad ok: %v", true, ok)
			} else if !bytes.Equal(tc.unpadded, got) {
				t.Errorf("want unpadded bytes: '%v', got unpadded bytes: '%v'", tc.unpadded, got)
			}
		})
	}
}

func TestPad(t *testing.T) {
	for _, tc := range validPaddingTestTable {
		t.Run(fmt.Sprintf("%v,%d", tc.unpadded, tc.blockSize), func(t *testing.T) {
			if got := Pad(tc.unpadded, tc.blockSize); !bytes.Equal(tc.padded, got) {
				t.Errorf("want: '%v', got: '%v'", tc.padded, got)
			}
		})
	}
}

func TestUnpad_ValidPadding_Succeeds(t *testing.T) {
	for _, tc := range validPaddingTestTable {
		t.Run(fmt.Sprintf("%v", tc.padded), func(t *testing.T) {
			if got, ok := Unpad(tc.padded, tc.blockSize); !ok {
				t.Error("want: ok == true, got: ok == false")
			} else if !bytes.Equal(tc.unpadded, got) {
				t.Errorf("want bytes: '%v', got bytes: '%v'", tc.unpadded, got)
			}
		})
	}
}

func TestUnpad_InvalidPadding_Fails(t *testing.T) {
	tt := []struct {
		plaintext []byte
		blockSize int
	}{
		{[]byte{}, 1},
		{[]byte("\x00"), 1},
		{[]byte("0\x00"), 1},
		{[]byte("\x03\x03"), 3},
		{[]byte("\x03\x03\x03\x03"), 3},
		{[]byte("00000\x01\x02\x03"), 4},
		{[]byte("00000\x01\x03\x03"), 4},
		{[]byte("00000\x03\x02\x03"), 4},
		{[]byte("00000\x04\x04\x04"), 4},
		{[]byte("000\xff"), 255},
	}

	for _, tc := range tt {
		t.Run(fmt.Sprintf("%v,%d", tc.plaintext, tc.blockSize), func(t *testing.T) {
			if got, ok := Unpad(tc.plaintext, tc.blockSize); ok {
				t.Error("want: ok == false, got: ok == true")
			} else if !bytes.Equal(tc.plaintext, got) {
				t.Errorf("want bytes: '%v', got bytes: '%v'", tc.plaintext, got)
			}
		})
	}
}
