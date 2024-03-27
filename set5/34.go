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
	*DecryptingReader
	*EncryptingWriter
}

func NewEncryptedReadWriter(rw io.ReadWriter, key []byte) *EncryptedReadWriter {
	return &EncryptedReadWriter{
		DecryptingReader: NewDecryptingReader(rw, key),
		EncryptingWriter: NewEncryptingWriter(rw, key),
	}
}

type DecryptingReader struct {
	dec  *gob.Decoder
	key  []byte
	rbuf []byte
}

func NewDecryptingReader(r io.Reader, key []byte) *DecryptingReader {
	return &DecryptingReader{
		dec: gob.NewDecoder(r),
		key: key,
	}
}

func (r *DecryptingReader) Read(b []byte) (n int, err error) {
	if len(r.rbuf) > 0 {
		n = copy(b, r.rbuf)
		b = b[n:]
		r.rbuf = r.rbuf[n:]
	}

	if len(b) == 0 {
		return n, nil
	}

	var msg AESCBCEncryptedMessage
	if err = r.dec.Decode(&msg); err != nil {
		return 0, fmt.Errorf("decoding: %w", err)
	}

	plaintext, err := cipher.CBCDecrypt(msg.Ciphertext, r.key, msg.IV)
	if err != nil {
		return 0, fmt.Errorf("decrypting: %w", err)
	}

	plaintext, err = pkcs7.Unpad(plaintext, aes.BlockSize)
	if err != nil {
		// TODO: Don't return error here.
		return 0, fmt.Errorf("removing PKCS#7 padding: %w", err)
	}

	nn := copy(b, plaintext)
	r.rbuf = plaintext[nn:]

	return n + nn, io.EOF
}

type EncryptingWriter struct {
	enc *gob.Encoder
	key []byte
}

func NewEncryptingWriter(w io.Writer, key []byte) *EncryptingWriter {
	return &EncryptingWriter{
		enc: gob.NewEncoder(w),
		key: key,
	}
}

func (rw *EncryptingWriter) Write(b []byte) (n int, err error) {
	iv := make([]byte, aes.BlockSize)
	if _, err = rand.Read(iv); err != nil {
		return 0, fmt.Errorf("generating random IV: %w", err)
	}

	b = pkcs7.Pad(b, aes.BlockSize)
	b, err = cipher.CBCEncrypt(b, rw.key, iv)
	if err != nil {
		return 0, fmt.Errorf("encrypting: %w", err)
	}

	if err = rw.enc.Encode(AESCBCEncryptedMessage{
		IV:         iv,
		Ciphertext: b,
	}); err != nil {
		return 0, fmt.Errorf("encoding: %w", err)
	}

	return len(b), nil
}

type EncryptedConnection struct {
	net.Conn
	rw *EncryptedReadWriter
}

func NewEncryptedConnection(conn net.Conn, key []byte) *EncryptedConnection {
	return &EncryptedConnection{
		Conn: conn,
		rw:   NewEncryptedReadWriter(conn, key),
	}
}

func (c *EncryptedConnection) Read(b []byte) (n int, err error) {
	return c.rw.Read(b)
}

func (c *EncryptedConnection) Write(b []byte) (n int, err error) {
	return c.rw.Write(b)
}

// Alice
func DeriveSharedSecretWithServer(conn net.Conn, p *big.Int, g int) ([]byte, error) {
	party, err := dh.NewParty(p, g)
	if err != nil {
		return nil, fmt.Errorf("initializing Diffie-Hellman party")
	}

	init := KeyExchangeInitiation{
		P:               p,
		G:               g,
		ClientPublicKey: party.PublicKey(),
	}

	if err = gob.NewEncoder(conn).Encode(init); err != nil {
		return nil, fmt.Errorf("sending key exchange initiation: %w", err)
	}

	var final KeyExchangeFinalization
	if err = gob.NewDecoder(conn).Decode(&final); err != nil {
		return nil, fmt.Errorf("receiving key exchange finalization: %w", err)
	}

	s := party.DeriveSharedSecret(final.ServerPublicKey)
	h := sha1.Sum(s)

	return h[:aes.BlockSize], nil
}

// Bob
func DeriveSharedSecretWithClient(conn net.Conn) ([]byte, error) {
	var init KeyExchangeInitiation
	if err := gob.NewDecoder(conn).Decode(&init); err != nil {
		return nil, fmt.Errorf("receiving key exchange initiation: %w", err)
	}

	party, err := dh.NewParty(init.P, init.G)
	if err != nil {
		return nil, fmt.Errorf("initializing Diffie-Hellman party")
	}

	final := KeyExchangeFinalization{ServerPublicKey: party.PublicKey()}
	if err = gob.NewEncoder(conn).Encode(final); err != nil {
		return nil, fmt.Errorf("sending key exchange finalization: %w", err)
	}

	s := party.DeriveSharedSecret(init.ClientPublicKey)
	h := sha1.Sum(s)

	return h[:aes.BlockSize], nil
}

// Mallory
// func KeyFixDiffieHellmanKeyExchange(
// 	client net.Conn,
// 	server net.Conn,
// ) ([]byte, error) {
// 	var init KeyExchangeInitiation
// 	if err := gob.NewDecoder(client).Decode(&init); err != nil {
// 		return nil, fmt.Errorf("receiving key exchange initiation: %w", err)
// 	}

// 	init.ClientPublicKey = init.P

// 	if err := gob.NewEncoder(server).Encode(init); err != nil {
// 		return nil, fmt.Errorf("sending parameter injected key exchange initiation: %w", err)
// 	}

// 	var final KeyExchangeFinalization
// 	if err := gob.NewDecoder(server).Decode(&final); err != nil {
// 		return nil, fmt.Errorf("receiving key exchange finalization: %w", err)
// 	}

// 	final.ServerPublicKey = init.P

// 	if err := gob.NewEncoder(client).Encode(final); err != nil {
// 		return nil, fmt.Errorf("sending parameter injected key exchange finalization: %w", err)
// 	}

// 	party, err := dh.NewParty(init.P, init.G)
// 	if err != nil {
// 		return nil, fmt.Errorf("initializing Diffie-Hellman party")
// 	}
// 	s := party.DeriveSharedSecret(init.P)
// 	h := sha1.Sum(s)

// 	return h[:aes.BlockSize], nil
// }

func Proxy(
	clientSiphon *DecryptingReader,
	serverSiphon *DecryptingReader,
	client,
	server net.Conn,
) error {
	defer client.Close()
	defer server.Close()

	// Fix the derived shared secret via parameter injection.
	var init KeyExchangeInitiation
	if err := gob.NewDecoder(client).Decode(&init); err != nil {
		return fmt.Errorf("receiving key exchange initiation: %w", err)
	}

	init.ClientPublicKey = init.P

	if err := gob.NewEncoder(server).Encode(init); err != nil {
		return fmt.Errorf("sending parameter injected key exchange initiation: %w", err)
	}

	var final KeyExchangeFinalization
	if err := gob.NewDecoder(server).Decode(&final); err != nil {
		return fmt.Errorf("receiving key exchange finalization: %w", err)
	}

	final.ServerPublicKey = init.P

	if err := gob.NewEncoder(client).Encode(final); err != nil {
		return fmt.Errorf("sending parameter injected key exchange finalization: %w", err)
	}

	party, err := dh.NewParty(init.P, init.G)
	if err != nil {
		return fmt.Errorf("initializing Diffie-Hellman party")
	}
	s := party.DeriveSharedSecret(init.P)
	h := sha1.Sum(s)

	key := h[:aes.BlockSize]

	// Proxy the connections while siphoning off data.
	clientR, clientW := io.Pipe()
	*clientSiphon = *NewDecryptingReader(clientR, key)

	serverR, serverW := io.Pipe()
	*serverSiphon = *NewDecryptingReader(serverR, key)

	done := make(chan error, 1)
	go func() {
		defer close(done)
		if _, err := io.Copy(server, io.TeeReader(client, clientW)); err != nil {
			done <- fmt.Errorf("proxying from Alice to Bob: %w", err)
		}
	}()

	if _, err := io.Copy(client, io.TeeReader(server, serverW)); err != nil {
		return fmt.Errorf("proxying from Bob to Alice: %w", err)
	}

	if err := <-done; err != nil {
		return err
	}

	return nil
}
