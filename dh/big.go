package dh

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math"
	"math/big"
)

// PublicKey represents the public key in a finite field Diffie-Hellman key
// exchange.
type PublicKey *big.Int

// PrivateKey represents the private key in a finite field Diffie-Hellman key
// exchange.
type PrivateKey *big.Int

// Party represents one of the two parties in a finite field Diffie-Hellman key
// exchange.
type Party struct {
	p    *big.Int   // modulus
	priv PrivateKey // private key
	pub  PublicKey  // public key
}

// NewParty initiates one of the two parties in a finite field Diffie-Hellman
// key exchange.
func NewParty(p *big.Int, g int) (*Party, error) {
	priv, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return nil, fmt.Errorf("generating private key: %w", err)
	}
	priv = priv.Mod(priv, p)

	pub := big.NewInt(int64(g))
	pub = pub.Exp(pub, priv, p)

	party := &Party{
		p:    p,
		priv: priv,
		pub:  pub,
	}

	return party, nil
}

// PublicKey returns the party's public key.
func (p *Party) PublicKey() PublicKey {
	return p.pub
}

// DeriveSharedSecret derives a shared secret from the remote party's public
// key.
func (p *Party) DeriveSharedSecret(remote PublicKey) []byte {
	s := new(big.Int).Exp(remote, p.priv, p.p)
	h := sha256.Sum256(s.Bytes())
	return h[:]
}
