// # ECB cut-and-paste
//
// Write a k=v parsing routine, as if for a structured cookie. The routine
// should take:
//
// 	foo=bar&baz=qux&zap=zazzle
//
// ... and produce:
//
// 	{
// 	  foo: 'bar',
// 	  baz: 'qux',
// 	  zap: 'zazzle'
// 	}
//
// (you know, the object; I don't care if you convert it to JSON).
//
// Now write a function that encodes a user profile in that format, given an
// email address. You should have something like:
//
// 	profile_for("foo@bar.com")
//
// ... and it should produce:
//
// 	{
// 	  email: 'foo@bar.com',
// 	  uid: 10,
// 	  role: 'user'
// 	}
//
// ... encoded as:
//
// 	email=foo@bar.com&uid=10&role=user
//
// Your "profile_for" function should _not_ allow encoding metacharacters
// (& and =). Eat them, quote them, whatever you want to do, but don't let
// people set their email address to "foo@bar.com&role=admin".
//
// Now, two more easy functions. Generate a random AES key, then:
//
// A. Encrypt the encoded user profile under the key; "provide" that to the "attacker".
// B. Decrypt the encoded user profile and parse it.
//
// Using only the user input to profile_for() (as an oracle to generate "valid"
// ciphertexts) and the ciphertexts themselves, make a role=admin profile.

package set2

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/saclark/cryptopals-go/aes"
	"github.com/saclark/cryptopals-go/pkcs7"
)

func ForgeAdminProfile(oracle func(string) ([]byte, error)) ([]byte, error) {
	// Inject the string "admin" with 11 bytes of padding, prepended with enough
	// "A"s to make "admin" start on the 17th byte of the ciphertext, giving us
	// back a ciphertext from which we can extract a valid "admin" block.
	//
	// email=AAAAAAAAAAadmin11111111111@example.com&uid=10&role=user333
	// |--------------||--------------||--------------||--------------|
	input := "AAAAAAAAAAadmin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b@example.com"
	ciphertext, err := oracle(input)
	if err != nil {
		return nil, fmt.Errorf("querying encryption oracle with \"%x\": %w", input, err)
	}

	// Cut out the "admin" ciphertext block.
	adminBlock := ciphertext[16:32]

	// Craft an email address of such length that the "user" role value will
	// start on the 49th byte of the ciphertext (e.g the start of a block).
	//
	// email=AAAAAAAAAAAAAAAAA@example.com&uid=10&role=userCCCCCCCCCCCC
	// |--------------||--------------||--------------||--------------|
	input = "AAAAAAAAAAAAAAAAA@example.com"
	ciphertext, err = oracle(input)
	if err != nil {
		return nil, fmt.Errorf("querying encryption oracle with \"%x\": %w", input, err)
	}

	// overwrite the "user" block with the "admin" block.
	copy(ciphertext[len(ciphertext)-16:], adminBlock)

	return ciphertext, nil
}

type UserProfileOracle struct {
	Key []byte
}

// NewUserProfileOracle implements an encryption oracle that takes an email
// address as input, URL encodes it as a user profile in the form
//
//	email={oracleInput}&uid=10&role=user
//
// and then encrypts that using AES in ECB mode under the same key upon each
// invocation. An attacker should be able to use this oracle to craft a valid
// ciphertext that decrypts to a user profile with role=admin. The key is also
// returned so attackers can verify their results.
func NewUserProfileOracle() (*UserProfileOracle, error) {
	key, err := randomBytes(aes.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("generating random key: %w", err)
	}
	return &UserProfileOracle{Key: key}, nil
}

// CreateEncryptedProfile is an encryption oracle that takes an email
// address as input, URL encodes it as a user profile in the form
//
//	email={oracleInput}&uid=10&role=user
//
// and then encrypts that using AES in ECB mode under the same key upon each
// invocation. An attacker should be able to use this oracle to craft a valid
// ciphertext that decrypts to a user profile with role=admin. The key is also
// returned so attackers can verify their results.
func (o *UserProfileOracle) CreateEncryptedProfile(emailAddress string) ([]byte, error) {
	profile := UserProfile{
		Email: string(emailAddress),
		UID:   10,
		Role:  "user",
	}
	plaintext := []byte(profile.urlEncode())
	plaintext = pkcs7.Pad(plaintext, aes.BlockSize)
	return aes.EncryptECB(plaintext, o.Key)
}

type UserProfile struct {
	Email string
	UID   int
	Role  string
}

func DecodeUserProfile(encodedProfile string) (UserProfile, error) {
	v, err := url.ParseQuery(encodedProfile)
	if err != nil {
		return UserProfile{}, fmt.Errorf("parsing encoded profile: %v", err)
	}
	uid, err := strconv.Atoi(v.Get("uid"))
	if err != nil {
		return UserProfile{}, fmt.Errorf("parsing uid: %v", err)
	}
	u := UserProfile{
		Email: v.Get("email"),
		UID:   uid,
		Role:  v.Get("role"),
	}
	return u, nil
}

// urlEncode encodes the user profile in the following format:
//
//	email={email}&uid={uid}&role={role}
//
// It only escapes "&" and "=" characters from the fields when encoding and
// always encodes the parameters in the same order, shown above. It does not do
// proper URL encoding because we want this to be more prone to ECB
// cut-and-pase attacks.
func (p *UserProfile) urlEncode() string {
	return fmt.Sprintf(
		"email=%s&uid=%d&role=%s",
		escapeMetaChars(p.Email),
		p.UID,
		escapeMetaChars(p.Role),
	)
}

func escapeMetaChars(s string) string {
	s = strings.ReplaceAll(s, "&", "%26")
	s = strings.ReplaceAll(s, "=", "%3D")
	return s
}
