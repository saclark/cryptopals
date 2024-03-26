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
	"io"
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

type EncryptedReadWriter struct {
	enc  *gob.Encoder
	dec  *gob.Decoder
	key  []byte
	rbuf []byte
}

func NewEncryptedReadWriter(rw io.ReadWriter, key []byte) *EncryptedReadWriter {
	return &EncryptedReadWriter{
		enc: gob.NewEncoder(rw),
		dec: gob.NewDecoder(rw),
		key: key,
	}
}

func (sc *EncryptedReadWriter) Read(b []byte) (n int, err error) {
	if len(sc.rbuf) > 0 {
		n = copy(b, sc.rbuf)
		b = b[n:]
		sc.rbuf = sc.rbuf[n:]
	}

	if len(b) == 0 {
		return n, nil
	}

	var msg AESCBCEncryptedMessage
	if err = sc.dec.Decode(&msg); err != nil {
		return 0, fmt.Errorf("decoding: %w", err)
	}

	plaintext, err := cipher.CBCDecrypt(msg.Ciphertext, sc.key, msg.IV)
	if err != nil {
		return 0, fmt.Errorf("decrypting: %w", err)
	}

	plaintext, err = pkcs7.Unpad(plaintext, aes.BlockSize)
	if err != nil {
		// TODO: Don't return error here.
		return 0, fmt.Errorf("removing PKCS#7 padding: %w", err)
	}

	nn := copy(b, plaintext)
	sc.rbuf = plaintext[nn:]

	return n + nn, io.EOF
}

func (sc *EncryptedReadWriter) Write(b []byte) (n int, err error) {
	iv := make([]byte, aes.BlockSize)
	if _, err = rand.Read(iv); err != nil {
		return 0, fmt.Errorf("generating random IV: %w", err)
	}

	b = pkcs7.Pad(b, aes.BlockSize)
	b, err = cipher.CBCEncrypt(b, sc.key, iv)
	if err != nil {
		return 0, fmt.Errorf("encrypting: %w", err)
	}

	if err = sc.enc.Encode(AESCBCEncryptedMessage{
		IV:         iv,
		Ciphertext: b,
	}); err != nil {
		return 0, fmt.Errorf("encoding: %w", err)
	}

	return len(b), nil
}

// Alice
func RequestDiffieHellmanKeyExchange(conn net.Conn, p *big.Int, g int) ([]byte, error) {
	party, err := dh.NewParty(p, g)
	if err != nil {
		return nil, fmt.Errorf("initializing Diffie-Hellman party")
	}

	enc := gob.NewEncoder(conn)
	dec := gob.NewDecoder(conn)

	init := KeyExchangeInitiation{
		P:               p,
		G:               g,
		ClientPublicKey: party.PublicKey(),
	}

	if err = enc.Encode(init); err != nil {
		return nil, fmt.Errorf("sending key exchange initiation: %w", err)
	}

	var final KeyExchangeFinalization
	if err = dec.Decode(&final); err != nil {
		return nil, fmt.Errorf("receiving key exchange finalization: %w", err)
	}

	s := party.DeriveSharedSecret(final.ServerPublicKey)
	h := sha1.Sum(s)

	return h[:aes.BlockSize], nil
}

// Bob
func AcceptDiffieHellmanKeyExchange(conn net.Conn) ([]byte, error) {
	enc := gob.NewEncoder(conn)
	dec := gob.NewDecoder(conn)

	var init KeyExchangeInitiation
	if err := dec.Decode(&init); err != nil {
		return nil, fmt.Errorf("receiving key exchange initiation: %w", err)
	}

	party, err := dh.NewParty(init.P, init.G)
	if err != nil {
		return nil, fmt.Errorf("initializing Diffie-Hellman party")
	}

	final := KeyExchangeFinalization{ServerPublicKey: party.PublicKey()}
	if err = enc.Encode(final); err != nil {
		return nil, fmt.Errorf("sending key exchange finalization: %w", err)
	}

	s := party.DeriveSharedSecret(init.ClientPublicKey)
	h := sha1.Sum(s)

	return h[:aes.BlockSize], nil
}

// Mallory
func KeyFixDiffieHellmanKeyExchange(
	clientConn net.Conn,
	serverConn net.Conn,
) ([]byte, error) {
	clientEnc := gob.NewEncoder(clientConn)
	clientDec := gob.NewDecoder(clientConn)
	serverEnc := gob.NewEncoder(serverConn)
	serverDec := gob.NewDecoder(serverConn)

	var init KeyExchangeInitiation
	if err := clientDec.Decode(&init); err != nil {
		return nil, fmt.Errorf("receiving key exchange initiation: %w", err)
	}

	init.ClientPublicKey = init.P

	if err := serverEnc.Encode(init); err != nil {
		return nil, fmt.Errorf("sending parameter injected key exchange initiation: %w", err)
	}

	var final KeyExchangeFinalization
	if err := serverDec.Decode(&final); err != nil {
		return nil, fmt.Errorf("receiving key exchange finalization: %w", err)
	}

	final.ServerPublicKey = init.P

	if err := clientEnc.Encode(final); err != nil {
		return nil, fmt.Errorf("sending parameter injected key exchange finalization: %w", err)
	}

	party, err := dh.NewParty(init.P, init.G)
	if err != nil {
		return nil, fmt.Errorf("initializing Diffie-Hellman party")
	}
	s := party.DeriveSharedSecret(init.P)
	h := sha1.Sum(s)

	return h[:aes.BlockSize], nil
}
