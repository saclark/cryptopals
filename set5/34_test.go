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

	alice, aliceMal := net.Pipe()
	bobMal, bob := net.Pipe()

	var aliceSiphon DecryptingReader
	var bobSiphon DecryptingReader
	Proxy(&aliceSiphon, &bobSiphon, aliceMal, bobMal)

	echoChan := make(chan []byte, 1)
	aliceSiphonChan := make(chan []byte)
	bobSiphonChan := make(chan []byte)
	errChan := make(chan error, 1)

	// MitM (Mallory)
	// go func() {
	// 	defer aliceMal.Close()
	// 	defer bobMal.Close()

	// 	key, err := KeyFixDiffieHellmanKeyExchange(aliceMal, bobMal)
	// 	if err != nil {
	// 		errChan <- fmt.Errorf("key fixing Diffie-Hellman key exchange: %w", err)
	// 		return
	// 	}

	// 	// alice -> aliceMal -> bobMal -> bob
	// 	//             |          |
	// 	//      aliceSiphon   bobSiphon

	// 	var wg sync.WaitGroup
	// 	aliceR, aliceW := io.Pipe()
	// 	bobR, bobW := io.Pipe()

	// 	go func() {
	// 		for {
	// 			dec := gob.NewDecoder(aliceR)
	// 			var msg AESCBCEncryptedMessage
	// 			if err = dec.Decode(&msg); err != nil {
	// 				errChan <- fmt.Errorf("decoding siphoned message sent from Alice to Bob: %w", err)
	// 				return
	// 			}

	// 			plaintext, err := cipher.CBCDecrypt(msg.Ciphertext, key, msg.IV)
	// 			if err != nil {
	// 				errChan <- fmt.Errorf("decrypting siphoned message sent from Alice to Bob: %w", err)
	// 				return
	// 			}

	// 			plaintext, err = pkcs7.Unpad(plaintext, aes.BlockSize)
	// 			if err != nil {
	// 				// TODO: Don't return error here.
	// 				errChan <- fmt.Errorf("unpadding siphoned message sent from Alice to Bob: %w", err)
	// 				return
	// 			}

	// 			aliceSiphonChan <- plaintext
	// 		}
	// 	}()

	// 	go func() {
	// 		for {
	// 			dec := gob.NewDecoder(bobR)
	// 			var msg AESCBCEncryptedMessage
	// 			if err = dec.Decode(&msg); err != nil {
	// 				errChan <- fmt.Errorf("decoding siphoned message sent from Bob to Alice: %w", err)
	// 				return
	// 			}

	// 			plaintext, err := cipher.CBCDecrypt(msg.Ciphertext, key, msg.IV)
	// 			if err != nil {
	// 				errChan <- fmt.Errorf("decrypting siphoned message sent from Bob to Alice: %w", err)
	// 				return
	// 			}

	// 			plaintext, err = pkcs7.Unpad(plaintext, aes.BlockSize)
	// 			if err != nil {
	// 				// TODO: Don't return error here.
	// 				errChan <- fmt.Errorf("unpadding siphoned message sent from Bob to Alice: %w", err)
	// 				return
	// 			}

	// 			bobSiphonChan <- plaintext
	// 		}
	// 	}()

	// 	wg.Add(1)
	// 	go func() {
	// 		defer wg.Done()
	// 		if _, err = io.Copy(bobMal, io.TeeReader(aliceMal, aliceW)); err != nil {
	// 			errChan <- fmt.Errorf("proxying from Alice to Bob: %w", err)
	// 			return
	// 		}
	// 	}()

	// 	wg.Add(1)
	// 	go func() {
	// 		defer wg.Done()
	// 		if _, err = io.Copy(aliceMal, io.TeeReader(bobMal, bobW)); err != nil {
	// 			errChan <- fmt.Errorf("proxying from Bob to Alice: %w", err)
	// 			return
	// 		}
	// 	}()

	// 	wg.Wait()
	// }()

	// Server (Bob)
	go func() {
		defer bob.Close()
		key, err := DeriveSharedSecretWithClient(bob)
		if err != nil {
			errChan <- fmt.Errorf("accepting Diffie-Hellman key exchange: %w", err)
			return
		}

		encrypted := NewEncryptedReadWriter(bob, key)

		msg, err := io.ReadAll(encrypted)
		if err != nil {
			errChan <- fmt.Errorf("reading message from Alice: %w", err)
			return
		}

		if _, err = encrypted.Write(msg); err != nil {
			errChan <- fmt.Errorf("writing echo to Alice: %w", err)
			return
		}
	}()

	// Client (Alice)
	go func() {
		defer alice.Close()
		key, err := DeriveSharedSecretWithServer(alice, p, g)
		if err != nil {
			errChan <- fmt.Errorf("requesting Diffie-Hellman key exchange: %w", err)
			return
		}

		encrypted := NewEncryptedReadWriter(alice, key)

		if _, err = encrypted.Write(msg); err != nil {
			errChan <- fmt.Errorf("writing message to Bob: %w", err)
			return
		}

		echo, err := io.ReadAll(encrypted)
		if err != nil {
			errChan <- fmt.Errorf("reading echo from Bob: %w", err)
			return
		}

		echoChan <- echo
	}()

	var aliceSiphonCount, bobSiphonCount int
	for {
		select {
		case err := <-errChan:
			t.Fatal(err)
		case aliceSiphon := <-aliceSiphonChan:
			if !bytes.Equal(msg, aliceSiphon) {
				t.Errorf("want decrypted siphon from Alice: '%x', got decrypted siphon from Alice: '%x'", msg, aliceSiphon)
			}
			aliceSiphonCount++
		case bobSiphon := <-bobSiphonChan:
			if !bytes.Equal(msg, bobSiphon) {
				t.Errorf("want decrypted siphon from Bob: '%x', got decrypted siphon from Bob: '%x'", msg, bobSiphon)
			}
			bobSiphonCount++
		case echo := <-echoChan:
			if !bytes.Equal(msg, echo) {
				t.Errorf("want echo: '%x', got echo: '%x'", msg, echo)
			}
			if aliceSiphonCount == 0 {
				t.Error("want plaintexts siphoned from Alice, got none")
			}
			if bobSiphonCount == 0 {
				t.Error("want plaintexts siphoned from Bob, got none")
			}
			return
		}
	}
}
