// # Implement and break HMAC-SHA1 with an artificial timing leak
//
// The psuedocode on Wikipedia should be enough. HMAC is very easy.
//
// Using the web framework of your choosing (Sinatra, web.py, whatever), write a
// tiny application that has a URL that takes a "file" argument and a
// "signature" argument, like so:
//
// 	http://localhost:9000/test?file=foo&signature=46b4ec586117154dacd49d664e5d63fdc88efb51
//
// Have the server generate an HMAC key, and then verify that the "signature" on
// incoming requests is valid for "file", using the "==" operator to compare the
// valid MAC for a file with the "signature" parameter (in other words, verify
// the HMAC the way any normal programmer would verify it).
//
// Write a function, call it "insecure_compare", that implements the ==
// operation by doing byte-at-a-time comparisons with early exit (ie, return
// false at the first non-matching byte).
//
// In the loop for "insecure_compare", add a 50ms sleep (sleep 50ms after each
// byte).
//
// Use your "insecure_compare" function to verify the HMACs on incoming
// requests, and test that the whole contraption works. Return a 500 if the MAC
// is invalid, and a 200 if it's OK.
//
// Using the timing leak in this application, write a program that discovers the
// valid MAC for any file.
//
// > # Why artificial delays?
// > Early-exit string compares are probably the most common source of
// > cryptographic timing leaks, but they aren't especially easy to exploit. In
// > fact, many timing leaks (for instance, any in C, C++, Ruby, or Python)
// > probably aren't exploitable over a wide-area network at all. To play with
// > attacking real-world timing leaks, you have to start writing low-level
// > timing code. We're keeping things cryptographic in these challenges.

package set4

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"time"
)

// NewSignatureTimingFunc returns a function that can be used to time how long
// a request to the vulnerable server with the given blob and chosen HMAC takes
// to respond, as well as whether the given HMAC is valid.
//
// For the sake of demonstrating the attack in a faster, more reliable manner,
// the response body of our vulnerable server may include a duration
// representing a total amount of simulated time "leaked" when comparing hashes.
// The returned function returns a duration that represents the returned
// simulated time added to the actual measured time, giving us a more consistent
// partially simulated timing result. When not simulating time, the server may
// return a duration of 0 or an empty response body, in which case the timing
// result represents the real, unsimulated request duration.
func NewLargeLeakSignatureTimingFunc(
	client *http.Client,
	baseURL string,
	blob []byte,
) func(
	ctx context.Context,
	signature []byte,
) (d time.Duration, valid bool, err error) {
	return func(ctx context.Context, signature []byte) (d time.Duration, valid bool, err error) {
		url := baseURL + "/blob?signature=" + hex.EncodeToString(signature)
		req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(blob))
		if err != nil {
			return 0, false, fmt.Errorf("building request: %w", err)
		}
		req.Header.Add("Content-Type", "application/octet-stream")

		t := time.Now()
		resp, err := client.Do(req)
		d = time.Since(t)
		if err != nil {
			return d, false, fmt.Errorf("sending request: %w", err)
		}
		defer resp.Body.Close()

		// Read amount of simulated time leakage from the response body.
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return d, false, fmt.Errorf("reading response body: %w", err)
		}

		// The response body must either be empty or a parse-able time.Duration
		// string.
		if len(b) > 0 {
			mockedDuration, err := time.ParseDuration(string(b))
			if err != nil {
				return d, false, fmt.Errorf("parsing non-empty response body as a duration: %w", err)
			}
			d += mockedDuration
		}

		switch resp.StatusCode {
		case 200:
			return d, true, nil
		case 500:
			return d, false, nil
		default:
			return d, false, fmt.Errorf("unexpected response status code: %d", resp.StatusCode)
		}
	}
}
