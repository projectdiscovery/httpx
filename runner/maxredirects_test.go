package runner

import (
	"testing"

	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/stretchr/testify/require"
)

// Options built in code leave MaxRedirects at 0, which made -fr follow no
// redirect at all for library users (discussion #2182).
func TestNewKeepsDefaultMaxRedirects(t *testing.T) {
	for _, tc := range []struct{ set, want int }{
		{0, httpx.DefaultOptions.MaxRedirects},
		{3, 3},
	} {
		r, err := New(&Options{FollowRedirects: true, MaxRedirects: tc.set})
		require.NoError(t, err)
		require.Equal(t, tc.want, r.hp.Options.MaxRedirects, "MaxRedirects=%d", tc.set)
		r.Close()
	}
}
