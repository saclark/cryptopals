// # Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection
//
// Use the code you just worked out to build a protocol and an "echo" bot. You
// don't actually have to do the network part of this if you don't want; just
// simulate that. The protocol is:
//
// *A->B*
// Send "p", "g", "A"
// *B->A*
// Send "B"
// *A->B*
// Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
// *B->A*
// Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
//
// (In other words, derive an AES key from DH with SHA1, use it in both
// directions, and do CBC with random IVs appended or prepended to the message).
//
// Now implement the following MITM attack:
//
// *A->M*
// Send "p", "g", "A"
// *M->B*
// Send "p", "g", "p"
// *B->M*
// Send "B"
// *M->A*
// Send "p"
// *A->M*
// Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
// *M->B*
// Relay that to B
// *B->M*
// Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
// *M->A*
// Relay that to A
//
// M should be able to decrypt the messages. "A" and "B" in the protocol --- the
// public keys, over the wire --- have been swapped out with "p". Do the DH math
// on this quickly to see what that does to the predictability of the key.
//
// Decrypt the messages from M's vantage point as they go by.
//
// Note that you don't actually have to inject bogus parameters to make this
// attack work; you could just generate Ma, MA, Mb, and MB as valid DH
// parameters to do a generic MITM attack. But do the parameter injection
// attack; it's going to come up again.

package set5

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/gob"
	"fmt"
	"math/big"
	"net"

	"github.com/saclark/cryptopals/cipher"
	"github.com/saclark/cryptopals/dh"
	"github.com/saclark/cryptopals/pkcs7"
)

type KeyExchangeInitiation struct {
	P               *big.Int
	G               int
	ClientPublicKey *big.Int
}

type KeyExchangeFinalization struct {
	ServerPublicKey *big.Int
}

type AESCBCEncryptedMessage struct {
	IV         []byte
	Ciphertext []byte
}

type SecureConnection struct {
	// net.Conn
	enc *gob.Encoder
	dec *gob.Decoder
	s   []byte
}

func (sc *SecureConnection) Read(b []byte) (n int, err error) {
	var msg AESCBCEncryptedMessage
	if err = sc.dec.Decode(&msg); err != nil {
		return 0, err
	}

	h := sha1.Sum(sc.s)
	k := h[:16]

	plaintext, err := cipher.CBCDecrypt(msg.Ciphertext, k, msg.IV)
	if err != nil {
		return 0, fmt.Errorf("AES-CBC decrypting message: %w", err)
	}

	plaintext, err = pkcs7.Unpad(plaintext, aes.BlockSize)
	if err != nil {
		return 0, fmt.Errorf("removing PKCS#7 padding: %w", err)
	}

	n = copy(b, plaintext)
	return n, nil
}

func (sc *SecureConnection) Write(b []byte) (n int, err error) {
	h := sha1.Sum(sc.s)
	k := h[:16]

	iv := make([]byte, aes.BlockSize)
	if _, err = rand.Read(iv); err != nil {
		return 0, fmt.Errorf("generating random IV: %w", err)
	}

	b = pkcs7.Pad(b, aes.BlockSize)
	b, err = cipher.CBCEncrypt(b, k, iv)
	if err != nil {
		return 0, fmt.Errorf("AES-CBC encrypting message: %w", err)
	}

	if err = sc.enc.Encode(AESCBCEncryptedMessage{
		IV:         iv,
		Ciphertext: b,
	}); err != nil {
		return 0, fmt.Errorf("sending AES-CBC encrypted message: %w", err)
	}

	return len(b), nil
}

// Alice
func RequestSecureConnection(conn net.Conn, p *big.Int, g int) (*SecureConnection, error) {
	party, err := dh.NewParty(p, g)
	if err != nil {
		return nil, fmt.Errorf("initializing Diffie-Hellman party")
	}

	sc := &SecureConnection{
		// Conn: conn,
		enc: gob.NewEncoder(conn),
		dec: gob.NewDecoder(conn),
	}

	init := KeyExchangeInitiation{
		P:               p,
		G:               g,
		ClientPublicKey: party.PublicKey(),
	}

	if err = sc.enc.Encode(init); err != nil {
		return nil, fmt.Errorf("sending key exchange initiation: %w", err)
	}

	var final KeyExchangeFinalization
	if err = sc.dec.Decode(&final); err != nil {
		return nil, fmt.Errorf("receiving key exchange finalization: %w", err)
	}

	sc.s = party.DeriveSharedSecret(final.ServerPublicKey)

	return sc, nil
}

// Bob
func AcceptSecureConnection(conn net.Conn) (*SecureConnection, error) {
	sc := &SecureConnection{
		// Conn: conn,
		enc: gob.NewEncoder(conn),
		dec: gob.NewDecoder(conn),
	}

	var init KeyExchangeInitiation
	if err := sc.dec.Decode(&init); err != nil {
		return nil, fmt.Errorf("receiving key exchange initiation: %w", err)
	}

	party, err := dh.NewParty(init.P, init.G)
	if err != nil {
		return nil, fmt.Errorf("initializing Diffie-Hellman party")
	}

	final := KeyExchangeFinalization{ServerPublicKey: party.PublicKey()}
	if err = sc.enc.Encode(final); err != nil {
		return nil, fmt.Errorf("sending key exchange finalization: %w", err)
	}

	sc.s = party.DeriveSharedSecret(init.ClientPublicKey)

	return sc, nil
}

// type DHKeyFixingMITM struct {
// 	net.Conn
// 	enc *gob.Encoder
// 	dec *gob.Decoder
// }

// func NewDHKeyFixingMITM(clientConn net.Conn, serverConn net.Conn) (*DHKeyFixingMITM, error) {
// 	panic("todo")
// }
