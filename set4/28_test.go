package set4

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestChallenge28_ResistsTampering(t *testing.T) {
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generating random key data: %v", err)
	}
	msg := make([]byte, 25)
	if _, err := rand.Read(msg); err != nil {
		t.Fatalf("generating random data: %v", err)
	}

	mac := SecretPrefixHMACSHA1(msg, key)

	for j := 0; j < len(msg); j++ {
		for b := byte(0x00); b < 0xff; b++ {
			tampMsg := bytes.Clone(msg)
			if tampMsg[j] == b {
				continue
			}
			tampMsg[j] = b
			tampMac := SecretPrefixHMACSHA1(tampMsg, key)
			if bytes.Equal(mac[:], tampMac[:]) {
				t.Fatalf("orig message MAC == tampered message MAC: orig message '%x', tampered message '%x', key: '%x', MAC: '%x'", msg, tampMsg, key, mac)
			}
		}
	}
}

func TestChallenge28_RequiresKey(t *testing.T) {
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generating random key data: %v", err)
	}
	msg := make([]byte, 25)
	if _, err := rand.Read(msg); err != nil {
		t.Fatalf("generating random data: %v", err)
	}

	mac := SecretPrefixHMACSHA1(msg, key)

	for j := 0; j < len(key); j++ {
		for b := byte(0x00); b < 0xff; b++ {
			otherKey := bytes.Clone(key)
			if otherKey[j] == b {
				continue
			}
			otherKey[j] = b
			tampMac := SecretPrefixHMACSHA1(msg, otherKey)
			if bytes.Equal(mac[:], tampMac[:]) {
				t.Fatalf("Same MAC calculated with different keys: orig key '%x', other key '%x', message: '%x', MAC: '%x'", key, otherKey, msg, mac)
			}
		}
	}
}
