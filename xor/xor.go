package xor

// BytesFixed sets dst[i] = x[i] ^ y[i] for all i in x and y. It panics if the
// length of x and y are not equal. If dst does not have length at least equal
// to x and y, BytesFixed panics without writing anything to dst.
func BytesFixed(dst, x, y []byte) {
	if len(x) != len(y) {
		panic("xor.BytesFixed: x and y not same length")
	}
	if len(dst) < len(x) {
		panic("xor.BytesFixed: dst too short")
	}
	for i := 0; i < len(x); i++ {
		dst[i] = x[i] ^ y[i]
	}
}

// BytesRepeatingByte sets dst[i] = s[i] ^ b for all i < len(s). If dst does not
// have length at least equal to s, BytesRepeatingByte panics without
// writing anything to dst.
func BytesRepeatingByte(dst, s []byte, b byte) {
	if len(dst) < len(s) {
		panic("xor.BytesRepeatingByte: dst too short")
	}
	for i, x := range s {
		dst[i] = x ^ b
	}
}

// BytesRepeating sets dst[i] = x[i%len(x)] ^ y[i%len(y)] for all
// i < n = max(len(x), len(y)) and returns the number of bytes written to dst.
// If dst does not have length at least n, BytesFixed panics without writing
// anything to dst.
func BytesRepeating(dst, x, y []byte) int {
	if len(x) == 0 || len(y) == 0 {
		return 0
	}
	n := len(x)
	if len(y) > n {
		n = len(y)
	}
	if len(dst) < n {
		panic("xor.BytesRepeating: dst too short")
	}
	for i := 0; i < n; i++ {
		dst[i] = x[i%len(x)] ^ y[i%len(y)]
	}
	return n
}
