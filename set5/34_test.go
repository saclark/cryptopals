package set5

import (
	"bytes"
	"fmt"
	"io"
	"math/big"
	"net"
	"testing"

	"github.com/saclark/cryptopals/internal/testutil"
)

func TestChallenge34(t *testing.T) {
	const g = 2
	pb := testutil.MustHexDecodeString("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff")
	p := new(big.Int).SetBytes(pb)

	msg := []byte("attack at dawn")

	alice, aliceMallory := net.Pipe()
	bobMallory, bob := net.Pipe()
	echoChan := make(chan []byte, 1)
	// mitmChan := make(chan []byte)
	errChan := make(chan error, 1)

	// MitM (Mallory)
	go func() {
		defer aliceMallory.Close()
		defer bobMallory.Close()
		aConn, bConn, err := MitMSecureConnection(aliceMallory, bobMallory)
		if err != nil {
			errChan <- err
			return
		}

		go func() {
			for {
				msg, err := io.ReadAll(bConn)
				if err != nil {
					errChan <- err
					return
				}

				// TODO: Decrypt.
				fmt.Printf("MitM bob->alice: %x\n", msg)

				if _, err = aConn.Write(msg); err != nil {
					errChan <- err
					return
				}
			}
		}()

		for {
			msg, err := io.ReadAll(aConn)
			if err != nil {
				errChan <- err
				return
			}

			// TODO: Decrypt.
			fmt.Printf("MitM alice->bob: %x\n", msg)

			if _, err = bConn.Write(msg); err != nil {
				errChan <- err
				return
			}
		}
	}()

	// Server (Bob)
	go func() {
		defer bob.Close()
		conn, err := AcceptSecureConnection(bob)
		if err != nil {
			errChan <- err
			return
		}

		msg, err := io.ReadAll(conn)
		if err != nil {
			errChan <- err
			return
		}

		if _, err = conn.Write(msg); err != nil {
			errChan <- err
			return
		}
	}()

	// Client (Alice)
	go func() {
		defer alice.Close()
		conn, err := RequestSecureConnection(alice, p, g)
		if err != nil {
			errChan <- err
			return
		}

		if _, err = conn.Write(msg); err != nil {
			errChan <- err
			return
		}

		echo, err := io.ReadAll(conn)
		if err != nil {
			errChan <- err
			return
		}

		echoChan <- echo
	}()

	select {
	case err := <-errChan:
		t.Fatal(err)
	case echo := <-echoChan:
		if !bytes.Equal(msg, echo) {
			t.Fatalf("want response to echo request, got request '%x' and response '%x'", msg, echo)
		}
	}
}
