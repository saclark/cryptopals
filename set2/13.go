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
// A. Encrypt the encoded user profile under the key; "provide" that to the
//    "attacker".
// B. Decrypt the encoded user profile and parse it.
//
// Using only the user input to profile_for() (as an oracle to generate "valid"
// ciphertexts) and the ciphertexts themselves, make a role=admin profile.

package set2

import (
	"fmt"
)

func ForgeAdminRoleECB(oracle func(string) ([]byte, error)) ([]byte, error) {
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
