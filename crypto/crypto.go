package crypto

func FixedXOR(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("arguments must be of the same length")
	}

	result := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		result[i] = a[i] ^ b[i]
	}

	return result
}

func SingleByteXOR(s []byte, k byte) []byte {
	result := make([]byte, len(s))
	for i, b := range s {
		result[i] = b ^ k
	}
	return result
}

func RepeatingXOR(a, b []byte) []byte {
	l := len(a)
	if len(b) > l {
		l = len(b)
	}

	result := make([]byte, l)
	for i := 0; i < l; i++ {
		result[i] = a[i%len(a)] ^ b[i%len(b)]
	}

	return result
}
