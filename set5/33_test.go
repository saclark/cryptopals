package set5

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/saclark/cryptopals/dh"
	"github.com/saclark/cryptopals/internal/testutil"
)

func TestChallenge33_Int32(t *testing.T) {
	const (
		p = 37
		g = 5
	)

	for i := 0; i < 1000; i++ {
		alice, err := dh.NewPartyInt32(p, g)
		if err != nil {
			t.Fatal(err)
		}

		bob, err := dh.NewPartyInt32(p, g)
		if err != nil {
			t.Fatal(err)
		}

		sA := alice.DeriveSharedSecret(bob.PublicKey())
		sB := bob.DeriveSharedSecret(alice.PublicKey())

		if !bytes.Equal(sA, sB) {
			t.Fatalf("want session keys to match, got session keys: %x, %x", sA, sB)
		}
	}
}

func TestChallenge33_BigInt(t *testing.T) {
	const g = 2
	pBytes := testutil.MustHexDecodeString("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff")
	p := new(big.Int).SetBytes(pBytes)

	for i := 0; i < 1000; i++ {
		alice, err := dh.NewParty(p, g)
		if err != nil {
			t.Fatal(err)
		}

		bob, err := dh.NewParty(p, g)
		if err != nil {
			t.Fatal(err)
		}

		sA := alice.DeriveSharedSecret(bob.PublicKey())
		sB := bob.DeriveSharedSecret(alice.PublicKey())

		if !bytes.Equal(sA, sB) {
			t.Fatalf("want session keys to match, got session keys: %x, %x", sA, sB)
		}
	}
}
