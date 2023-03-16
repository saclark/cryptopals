package pkcs7

import (
	"bytes"
	"errors"
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
				t.Errorf("want padded bytes: '%x', got padded bytes: '%x'", tc.padded, got)
			}
			if got, err := Unpad(got, tc.blockSize); err != nil {
				t.Errorf("want Unpad err: 'nil', got Unpad err: '%v'", err)
			} else if !bytes.Equal(tc.unpadded, got) {
				t.Errorf("want unpadded bytes: '%x', got unpadded bytes: '%x'", tc.unpadded, got)
			}
		})
	}
}

func TestPad(t *testing.T) {
	for _, tc := range validPaddingTestTable {
		t.Run(fmt.Sprintf("%v,%d", tc.unpadded, tc.blockSize), func(t *testing.T) {
			if got := Pad(tc.unpadded, tc.blockSize); !bytes.Equal(tc.padded, got) {
				t.Errorf("want: '%x', got: '%x'", tc.padded, got)
			}
		})
	}
}

func TestUnpad_ValidPadding_Succeeds(t *testing.T) {
	for _, tc := range validPaddingTestTable {
		t.Run(fmt.Sprintf("%v", tc.padded), func(t *testing.T) {
			if got, err := Unpad(tc.padded, tc.blockSize); err != nil {
				t.Errorf("want: 'nil', got: '%v'", err)
			} else if !bytes.Equal(tc.unpadded, got) {
				t.Errorf("want bytes: '%x', got bytes: '%x'", tc.unpadded, got)
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
			_, err := Unpad(tc.plaintext, tc.blockSize)
			if !errors.Is(err, ErrInvalidPadding) {
				t.Errorf("want: '%v', got: '%v'", ErrInvalidPadding, err)
			}
		})
	}
}
