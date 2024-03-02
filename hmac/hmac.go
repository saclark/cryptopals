package hmac

type Hash interface {
	Size() int
	BlockSize() int
	Sum(message []byte) []byte
}

func New(hash Hash, key []byte) Hash {
	if len(key) > hash.BlockSize() {
		key = hash.Sum(key)
	}
	if diff := hash.BlockSize() - len(key); diff > 0 {
		key = append(key, make([]byte, diff)...)
	}

	oKeyPad := make([]byte, len(key))
	for i, k := range key {
		oKeyPad[i] = k ^ 0x5c
	}

	iKeyPad := make([]byte, len(key))
	for i, k := range key {
		iKeyPad[i] = k ^ 0x36
	}

	return &hmacHash{
		h:       hash,
		oKeyPad: oKeyPad,
		iKeyPad: iKeyPad,
	}
}

type hmacHash struct {
	h       Hash
	oKeyPad []byte
	iKeyPad []byte
}

func (h *hmacHash) Sum(message []byte) []byte {
	return h.h.Sum(append(h.oKeyPad, h.h.Sum(append(h.iKeyPad, message...))...))
}

func (h *hmacHash) BlockSize() int {
	return h.h.BlockSize()
}

func (h *hmacHash) Size() int {
	return h.h.Size()
}
