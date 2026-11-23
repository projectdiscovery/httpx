package runner

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestFilterOperatorParse(t *testing.T) {
	f := FilterOperator{flag: "-mrt, -match-response-time"}

	t.Run("valid", func(t *testing.T) {
		for _, tc := range []struct {
			in       string
			operator string
			value    time.Duration
		}{
			{in: "<1s", operator: "<", value: time.Second},
			{in: ">1s", operator: ">", value: time.Second},
			{in: "=1s", operator: "=", value: time.Second},
			{in: "<=1s", operator: "<=", value: time.Second},
			{in: ">=1s", operator: ">=", value: time.Second},
			{in: "!=1s", operator: "!=", value: time.Second},
			{in: "<100ms", operator: "<", value: 100 * time.Millisecond},
			// A bare number is read as seconds.
			{in: ">=5", operator: ">=", value: 5 * time.Second},
			// Surrounding spaces are trimmed.
			{in: ">= 5s ", operator: ">=", value: 5 * time.Second},
		} {
			t.Run(tc.in, func(t *testing.T) {
				operator, value, err := f.Parse(tc.in)
				require.NoError(t, err)
				require.Equal(t, tc.operator, operator)
				require.Equal(t, tc.value, value)
			})
		}
	})

	t.Run("rejected", func(t *testing.T) {
		for _, in := range []string{
			// No operator at all.
			"1s",
			"",
			// An operator with nothing after it.
			">=",
			// Not a number and not a duration.
			">=abc",
			// A bare number too large to hold as a duration once seconds are
			// added. This used to come back as 0 with no error, which turned
			// -mrt into a filter that matched every host.
			">=10000000000",
			">=99999999999999999999",
		} {
			t.Run(in, func(t *testing.T) {
				_, value, err := f.Parse(in)
				require.Error(t, err, "expected %q to be rejected", in)
				require.Zero(t, value)
			})
		}
	})
}
