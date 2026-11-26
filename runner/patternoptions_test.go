package runner

import (
	"strings"
	"testing"

	"github.com/projectdiscovery/goflags"
	"github.com/stretchr/testify/require"
)

// -ms and -fs compare literal strings, so a `#` in the pattern is part of it.
// The goflags option set they used to share strips `#` comments, which emptied
// patterns like "#main" and truncated patterns like "Admin#zzz" to "admin".
func TestPatternFlagsKeepHash(t *testing.T) {
	for _, value := range []string{"#main", "#nothere", "Admin#zzz", "id=#main"} {
		actual, err := goflags.ToStringSlice(value, normalizedPatternStringSliceOptions)
		require.NoError(t, err, value)
		require.Len(t, actual, 1, value)
		// The stored pattern is lowercased, as it was before, because matching
		// goes through stringsutil.ContainsAnyI. The `#` and the text after it
		// now survive, which is the point of this test.
		require.Equal(t, strings.ToLower(value), actual[0], value)
	}
}

func TestPatternFlagsKeepSplittingAndTrimming(t *testing.T) {
	tests := []struct {
		value    string
		expected []string
	}{
		{"admin,login", []string{"admin", "login"}},
		{" admin , login ", []string{"admin", "login"}},
		{"isAdmin,", []string{"isadmin"}},
		{"", nil},
		{"   ", nil},
	}
	for _, test := range tests {
		actual, err := goflags.ToStringSlice(test.value, normalizedPatternStringSliceOptions)
		require.NoError(t, err, test.value)
		require.Equal(t, test.expected, actual, test.value)
	}
}
