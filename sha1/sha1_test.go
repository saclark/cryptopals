package sha1

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"testing"
)

func TestSum_MatchesStdLibSha1(t *testing.T) {
	data := make([]byte, (BlockSize*2)+1)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("creating random test data: %v", err)
	}
	for i := 0; i <= len(data); i++ {
		input := data[:i]
		want := sha1.Sum(input)
		got := Sum(input)
		if !bytes.Equal(want[:], got[:]) {
			t.Fatalf("[%d]: want: '%x', got: '%x'", i, want, got)
		}
	}
}
