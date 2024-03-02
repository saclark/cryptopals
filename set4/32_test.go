package set4

import (
	"bytes"
	"context"
	"flag"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/saclark/cryptopals/attack"
	"github.com/saclark/cryptopals/hmac"
	"github.com/saclark/cryptopals/internal/testutil"
	"github.com/saclark/cryptopals/sha1"
)

// A comma separated list of parameters denoting:
//
// 1. The sleep duration for each check of each byte of the signature
// 2. Whether or not calls to sleep should be real (value: 'real') or fake (value: 'fake').
// 3. Max concurrent requests
// 4. Top candidate count
// 5. Top candidate sample count
var chal32Params = flag.String("chal32", "50µs,fake,1,5,5", "Parameters for challenge 32")

func TestChallenge32(t *testing.T) {
	params, err := parseTimingAttackTestParams(*chal32Params)
	if err != nil {
		t.Fatal(err)
	}

	key := testutil.MustRandomBytes(sha1.BlockSize)
	h := hmac.New(sha1Hash{}, key)
	bytesEq := createLeakyBytesEqual(params.timingLeak, params.fakeTime)
	handler := handleAuthenticatedFileUpload(h, bytesEq)
	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	blob := testutil.MustRandomBytes(16)
	want := h.Sum(blob)

	timeRequest := NewSmallLeakSignatureTimingFunc(ts.Client(), ts.URL, blob)
	got, err := attack.ExploitTimingLeak(
		context.Background(), // tests time out after 10 minutes by default.
		sha1.Size,
		timeRequest,
		params.maxConcurrentRequests,
		params.topCandidateCount,
		params.topCandidateSampleCount,
		t.Logf,
	)
	if err != nil {
		t.Fatalf("want signature: '%x', got error: %v", want, err)
	}

	if !bytes.Equal(want, got) {
		t.Fatalf("want: '%x', got: '%x'", want, got)
	}
}
