// #Break HMAC-SHA1 with a slightly less artificial timing leak
//
// Reduce the sleep in your "insecure_compare" until your previous solution
// breaks. (Try 5ms to start.)
//
// Now break it again.

package set4

import (
	"context"
	"net/http"
	"time"
)

// NewSmallLeakSignatureTimingFunc is just the same as
// NewLargeLeakSignatureTimingFunc. Turns out my solution to Challenge 31 also
// works for solving Challenge 32.
func NewSmallLeakSignatureTimingFunc(
	client *http.Client,
	baseURL string,
	blob []byte,
) func(ctx context.Context, signature []byte) (d time.Duration, valid bool, err error) {
	return NewLargeLeakSignatureTimingFunc(client, baseURL, blob)
}
