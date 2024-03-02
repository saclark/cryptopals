package dh

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
)

// PublicKeyInt32 represents the public key in a pedagogical finite field
// Diffie-Hellman key exchange using small 32-bit parameters and key pairs.
type PublicKeyInt32 int32

// PrivateKeyInt32 represents the private key in a pedagogical finite field
// Diffie-Hellman key exchange using small 32-bit parameters and key pairs.
type PrivateKeyInt32 int32

// PartyInt32 represents one of the two parties in a pedagogical finite field
// Diffie-Hellman key exchange using small 32-bit parameters and key pairs.
type PartyInt32 struct {
	p    int32           // modulus
	priv PrivateKeyInt32 // private key
	pub  PublicKeyInt32  // public key
}

// NewPartyInt32 initiates one of the two parties in a pedagogical
// finite field Diffie-Hellman key exchange using small 32-bit parameters and
// key pairs.
func NewPartyInt32(p, g int32) (*PartyInt32, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt32))
	if err != nil {
		return nil, fmt.Errorf("generating random int32: %w", err)
	}

	priv := int32(n.Int64()) % p
	pub := modExp(g, priv, p)

	party := &PartyInt32{
		p:    p,
		priv: PrivateKeyInt32(priv),
		pub:  PublicKeyInt32(pub),
	}

	return party, nil
}

// PublicKey returns the party's public key.
func (p *PartyInt32) PublicKey() PublicKeyInt32 {
	return p.pub
}

// DeriveSharedSecret derives a shared secret from the remote party's public
// key.
func (p *PartyInt32) DeriveSharedSecret(remote PublicKeyInt32) []byte {
	s := modExp(int32(remote), int32(p.priv), p.p)
	sBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(sBytes, uint32(s))
	h := sha256.Sum256(sBytes)
	return h[:]
}

// modExp performs memory-efficient modular exponentiation.
func modExp(base, exp, mod int32) int32 {
	if mod == 1 {
		return 0
	}
	result := int32(1)
	for i := int32(0); i < exp; i++ {
		result = (base * result) % mod
	}
	return result
}
