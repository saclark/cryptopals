package xor

import (
	"bytes"
	"fmt"
	"testing"
)

func TestBytesFixed(t *testing.T) {
	tt := []struct {
		x, y, xy []byte
	}{
		{
			x:  []byte{0x00, 0x00, 0x01, 0x01},
			y:  []byte{0x00, 0x01, 0x00, 0x01},
			xy: []byte{0x00, 0x01, 0x01, 0x00},
		},
		{
			x:  []byte("abc123!@#"),
			y:  []byte("^&*QWE789"),
			xy: []byte("\x3f\x44\x49\x60\x65\x76\x16\x78\x1a"),
		},
	}

	for _, tc := range tt {
		t.Run(fmt.Sprintf("%v,%v", tc.x, tc.y), func(t *testing.T) {
			got := make([]byte, len(tc.x))

			// x ⊕ y = xy
			BytesFixed(got, tc.x, tc.y)
			if !bytes.Equal(tc.xy, got) {
				t.Fatalf("x ⊕ y != xy: want: '%x', got: '%x'", tc.xy, got)
			}

			// y ⊕ x = xy
			BytesFixed(got, tc.y, tc.x)
			if !bytes.Equal(tc.xy, got) {
				t.Fatalf("y ⊕ x != xy: want: '%x', got: '%x'", tc.xy, got)
			}

			// x ⊕ xy = y
			BytesFixed(got, tc.x, tc.xy)
			if !bytes.Equal(tc.y, got) {
				t.Fatalf("x ⊕ xy != y: want: '%x', got: '%x'", tc.y, got)
			}

			// y ⊕ xy = x
			BytesFixed(got, tc.y, tc.xy)
			if !bytes.Equal(tc.x, got) {
				t.Fatalf("y ⊕ xy != x: want: '%x', got: '%x'", tc.x, got)
			}
		})
	}
}

func TestBytesRepeatingByte(t *testing.T) {
	tt := []struct {
		x  []byte
		b  byte
		xb []byte
	}{
		{
			x:  []byte{0x00, 0x01},
			b:  0x00,
			xb: []byte{0x00, 0x01},
		},
		{
			x:  []byte{0x00, 0x01},
			b:  0x01,
			xb: []byte{0x01, 0x00},
		},
		{
			x:  []byte("abc123!@#"),
			b:  byte('X'),
			xb: []byte("\x39\x3a\x3b\x69\x6a\x6b\x79\x18\x7b"),
		},
	}

	for _, tc := range tt {
		t.Run(fmt.Sprintf("%v,%v", tc.x, tc.b), func(t *testing.T) {
			got := make([]byte, len(tc.x))

			// x ⊕ b = xb
			BytesRepeatingByte(got, tc.x, tc.b)
			if !bytes.Equal(tc.xb, got) {
				t.Fatalf("x ⊕ b != xb: want: '%x', got: '%x'", tc.xb, got)
			}

			// xb ⊕ b = x
			BytesRepeatingByte(got, tc.xb, tc.b)
			if !bytes.Equal(tc.x, got) {
				t.Fatalf("xb ⊕ b != x: want: '%x', got: '%x'", tc.xb, got)
			}
		})
	}
}

func TestBytesRepeating(t *testing.T) {
	tt := []struct {
		short, long, shortlong []byte
		n                      int
	}{
		{
			short:     []byte{},
			long:      []byte{0x00, 0x00, 0x01, 0x01},
			shortlong: []byte{},
			n:         0,
		},
		{
			short:     []byte{0x00, 0x01},
			long:      []byte{0x00, 0x00, 0x01, 0x01},
			shortlong: []byte{0x00, 0x01, 0x01, 0x00},
			n:         4,
		},
		{
			short:     []byte("^&*QWE789"),
			long:      []byte("abcdefg123456!@#$%^"),
			shortlong: []byte("\x3f\x44\x49\x35\x32\x23\x50\x09\x0b\x6d\x12\x1f\x67\x76\x05\x14\x1c\x1c\x00"),
			n:         19,
		},
	}

	for _, tc := range tt {
		t.Run(fmt.Sprintf("%v,%v", tc.short, tc.long), func(t *testing.T) {
			got := make([]byte, len(tc.long))

			// short ⊕ long = shortlong
			n := BytesRepeating(got, tc.short, tc.long)
			if tc.n != n {
				t.Errorf("want n: '%d', got n: '%d'", tc.n, n)
			}
			if n > 0 && !bytes.Equal(tc.shortlong, got) {
				t.Fatalf("short ⊕ long != shortlong: want: '%x', got: '%x'", tc.shortlong, got)
			}

			// long ⊕ short = shortlong
			n = BytesRepeating(got, tc.long, tc.short)
			if tc.n != n {
				t.Errorf("want n: '%d', got n: '%d'", tc.n, n)
			}
			if n > 0 && !bytes.Equal(tc.shortlong, got) {
				t.Fatalf("long ⊕ short != shortlong: want: '%x', got: '%x'", tc.shortlong, got)
			}

			// short ⊕ shortlong = long
			n = BytesRepeating(got, tc.short, tc.shortlong)
			if tc.n != n {
				t.Errorf("want n: '%d', got n: '%d'", tc.n, n)
			}
			if n > 0 && !bytes.Equal(tc.long, got) {
				t.Fatalf("short ⊕ shortlong != long: want: '%x', got: '%x'", tc.long, got)
			}
		})
	}
}
