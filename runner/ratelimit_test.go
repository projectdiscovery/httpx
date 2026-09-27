package runner

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRunnerRateLimiter(t *testing.T) {
	for _, tc := range []struct {
		name    string
		options Options
	}{
		{name: "per second", options: Options{RateLimit: 1}},
		{name: "per minute", options: Options{RateLimitMinute: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := New(&tc.options)
			require.NoError(t, err)
			t.Cleanup(r.Close)
			require.True(t, r.ratelimiter.CanTake())
			r.ratelimiter.Take()
			// The runner must observe the worker's token count, rather than a
			// copy of the initial count made when constructing the runner.
			require.Eventually(t, func() bool {
				return !r.ratelimiter.CanTake()
			}, 500*time.Millisecond, time.Millisecond)
		})
	}
}

func TestRunnerUnlimitedRateLimiter(t *testing.T) {
	// Unlimited limiters replenish every millisecond. Repeated construction
	// exercises initialization concurrently with replenishment under -race.
	for range 10 {
		r, err := New(&Options{})
		require.NoError(t, err)
		r.ratelimiter.Take()
		require.True(t, r.ratelimiter.CanTake())
		r.Close()
	}
}
