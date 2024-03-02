package set4

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/saclark/cryptopals/attack"
	"github.com/saclark/cryptopals/hmac"
	"github.com/saclark/cryptopals/internal/testutil"
	"github.com/saclark/cryptopals/sha1"
)

// A comma separated list of parameters denoting:
//
// 1. The sleep duration for each check of each byte of the signature
// 2. Whether or not calls to Sleep should be real ('real') or faked ('fake').
// 3. Max concurrent requests
// 4. Top candidate count
// 5. Top candidate sample count
//
// When testing in real time, the max concurrent requests parameter should be
// increased (I've had good success with 100 max concurrent requests) or else
// the test will take a very long time (and `go test` will likely time-out).
var chal31Params = flag.String("chal31", "50ms,fake,1,1,1", "Parameters for challenge 31")

func TestChallenge31(t *testing.T) {
	params, err := parseTimingAttackTestParams(*chal31Params)
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

	timeRequest := NewLargeLeakSignatureTimingFunc(ts.Client(), ts.URL, blob)
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

// sha1Hash wraps package github.com/saclark/cryptopals/sha1 in the interface
// required by package github.com/saclark/cryptopals/hmac.
type sha1Hash struct{}

func (sha1Hash) Size() int {
	return sha1.Size
}

func (sha1Hash) BlockSize() int {
	return sha1.BlockSize
}

func (sha1Hash) Sum(message []byte) []byte {
	sum := sha1.Sum(message)
	return sum[:]
}

// handleAuthenticatedFileUpload implements a server endpoint that returns a 500
// error if the uploaded signature does not match the uploaded blob.
func handleAuthenticatedFileUpload(
	h hmac.Hash,
	leakyHashComparison func([]byte, []byte) (time.Duration, bool),
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/blob" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method != "POST" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Content-Type") != "application/octet-stream" {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}

		blob, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		providedSignature, err := hex.DecodeString(r.URL.Query().Get("signature"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		actualSignature := h.Sum(blob)

		simulatedLeakage, ok := leakyHashComparison(actualSignature, providedSignature)
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
		}

		w.Header().Add("Content-Type", "text/plain")
		io.WriteString(w, simulatedLeakage.String())
	}
}

func createLeakyBytesEqual(
	timingLeak time.Duration,
	fakeTime bool,
) func([]byte, []byte) (time.Duration, bool) {
	return func(a, b []byte) (time.Duration, bool) {
		var t time.Duration
		if len(a) != len(b) {
			return t, false
		}
		for i := 0; i < len(a); i++ {
			if a[i] != b[i] {
				return t, false
			}
			if fakeTime {
				t += timingLeak
			} else {
				time.Sleep(timingLeak)
			}
		}
		return t, true
	}
}

type timingAttackTestParams struct {
	timingLeak              time.Duration
	fakeTime                bool
	maxConcurrentRequests   int
	topCandidateCount       int
	topCandidateSampleCount int
}

func parseTimingAttackTestParams(s string) (timingAttackTestParams, error) {
	var opts timingAttackTestParams
	var err error
	args := strings.Split(s, ",")
	if len(args) != 5 {
		return timingAttackTestParams{}, errors.New("too few timing attack test parameters")
	}
	if opts.timingLeak, err = time.ParseDuration(args[0]); err != nil {
		return timingAttackTestParams{}, fmt.Errorf("invalid timing leak duration value: %w", err)
	}
	switch args[1] {
	case "real":
		opts.fakeTime = false
	case "fake":
		opts.fakeTime = true
	default:
		return timingAttackTestParams{}, errors.New("invalid timing type value: must be 'real' or 'fake'")
	}
	if opts.maxConcurrentRequests, err = strconv.Atoi(args[2]); err != nil {
		return timingAttackTestParams{}, fmt.Errorf("invalid max concurrent requests value: %w", err)
	}
	if opts.topCandidateCount, err = strconv.Atoi(args[3]); err != nil {
		return timingAttackTestParams{}, fmt.Errorf("invalid top candidate count value: %w", err)
	}
	if opts.topCandidateSampleCount, err = strconv.Atoi(args[4]); err != nil {
		return timingAttackTestParams{}, fmt.Errorf("invalid top candidate sample count value: %w", err)
	}
	return opts, nil
}
