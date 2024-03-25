package set5

import (
	"fmt"
	"io"
	"math/big"
	"net"
	"testing"

	"github.com/saclark/cryptopals/internal/testutil"
)

func TestChallenge34(t *testing.T) {
	const g = 2
	pBytes := testutil.MustHexDecodeString("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff")
	p := new(big.Int).SetBytes(pBytes)

	client, server := net.Pipe()
	defer client.Close()

	// TODO: Better error handling.
	go func() {
		defer server.Close()
		bob, err := AcceptSecureConnection(server)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println("bob reading")
		msg, err := io.ReadAll(bob)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Printf("bob writing: %s\n", msg)
		// if _, err := bob.Write(msg); err != nil {
		// 	fmt.Println(err)
		// 	return
		// }
	}()

	alice, err := RequestSecureConnection(client, p, g)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("alice writing")
	msg := []byte("Hello, World!")
	if _, err := alice.Write(msg); err != nil {
		t.Fatal(err)
	}

	// fmt.Println("alice reading")
	// echo, err := io.ReadAll(alice)
	// if err != nil {
	// 	t.Fatal(err)
	// }

	// if !bytes.Equal(msg, echo) {
	// 	t.Fatalf("want response to echo request, got request '%s' and response '%s'", msg, echo)
	// }
}
