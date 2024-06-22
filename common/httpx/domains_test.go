package httpx

import (
	_ "embed"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

//go:embed test-data/hackerone.html
var rawResponse string

func TestBodyGrabDoamins(t *testing.T) {
	ht, err := New(&DefaultOptions)
	require.Nil(t, err)
	resposne := &Response{
		Raw: rawResponse,
	}
	bd := ht.BodyDomainGrab(resposne)

	sort.Strings(bd.Domains)
	sort.Strings(bd.Fqdns)

	t.Run("body domain grab", func(t *testing.T) {
		require.Equal(t, 24, len(bd.Domains))
		require.Equal(t, 16, len(bd.Fqdns))
	})
}
