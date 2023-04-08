package set2

import (
	"crypto/aes"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/saclark/cryptopals/cipher"
	"github.com/saclark/cryptopals/internal/testutil"
	"github.com/saclark/cryptopals/pkcs7"
)

// ECB cut-and-paste
// See: https://www.cryptopals.com/sets/2/challenges/13
func TestChallenge13(t *testing.T) {
	oracle := NewECBCutAndPasteOracle()

	encryptedForge, err := ForgeAdminRoleECB(oracle.CreateEncryptedProfile)
	if err != nil {
		t.Fatalf("forging admin profile: %v", err)
	}

	decryptedForge, err := cipher.ECBDecrypt(encryptedForge, oracle.Key)
	if err != nil {
		t.Fatalf("decrypting encoded profile: %v", err)
	}

	unpaddedForge, err := pkcs7.Unpad(decryptedForge, aes.BlockSize)
	if err != nil {
		t.Fatalf("unpadding encoded profile '%x': %v", unpaddedForge, err)
	}

	forgedProfile, err := DecodeUserProfile(string(unpaddedForge))
	if err != nil {
		t.Fatalf("decoding encoded profile: %v", err)
	}

	if want := "admin"; want != forgedProfile.Role {
		t.Errorf("want: '%s', got: '%s', encoded profile = %s", want, forgedProfile.Role, unpaddedForge)
	}
}

// ECBCutAndPasteOracle implements an encryption oracle that takes an email
// address as input, escapes any "&" any "=" characters, encodes it as a user
// profile in the form:
//
//	email={oracleInput}&uid=10&role=user
//
// and then encrypts that using AES in ECB mode under the same key upon each
// invocation. An attacker should be able to use this oracle to craft a valid
// ciphertext that decrypts to a user profile with "role=admin". Attackers can
// use Key to verify their attacks.
type ECBCutAndPasteOracle struct {
	Key []byte
}

// NewECBCutAndPasteOracle creates a new ECBCutAndPasteOracle with a randomly
// generated Key.
func NewECBCutAndPasteOracle() *ECBCutAndPasteOracle {
	key := testutil.MustRandomBytes(aes.BlockSize)
	return &ECBCutAndPasteOracle{Key: key}
}

// CreateEncryptedProfile acts as the encryption oracle.
func (o *ECBCutAndPasteOracle) CreateEncryptedProfile(emailAddress string) ([]byte, error) {
	profile := UserProfile{
		Email: string(emailAddress),
		UID:   10,
		Role:  "user",
	}
	plaintext := []byte(profile.urlEncodeProfile())
	plaintext = pkcs7.Pad(plaintext, aes.BlockSize)
	return cipher.ECBEncrypt(plaintext, o.Key)
}

type UserProfile struct {
	Email string
	UID   int
	Role  string
}

// DecodeUserProfile is provided as a convenince for attackers when verifying
// their attacks.
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

// urlEncodeProfile encodes the user profile in the following format:
//
//	email={email}&uid={uid}&role={role}
//
// It only escapes "&" and "=" characters from the fields when encoding and
// always encodes the parameters in the same order, shown above. It does not do
// proper URL encoding because we want this to be more prone to ECB
// cut-and-pase attacks.
func (p *UserProfile) urlEncodeProfile() string {
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
