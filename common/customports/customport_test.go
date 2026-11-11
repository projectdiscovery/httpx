package customport

import (
	"testing"

	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/stretchr/testify/require"
)

// A port that both an http and an https entry name becomes http&https, but only
// that port: the rest of the range keeps its own scheme.
func TestSetRangeMergesProtocolPerPort(t *testing.T) {
	Ports = make(map[int]string)
	t.Cleanup(func() { Ports = make(map[int]string) })

	var ports CustomPorts
	require.NoError(t, ports.Set("http:8081,https:8080-8082"))

	require.Equal(t, map[int]string{
		8080: httpx.HTTPS,
		8081: httpx.HTTPandHTTPS,
		8082: httpx.HTTPS,
	}, Ports)
}

func TestSetRangeReportsLastPort(t *testing.T) {
	Ports = make(map[int]string)
	t.Cleanup(func() { Ports = make(map[int]string) })

	var ports CustomPorts
	err := ports.Set("8080-70000")
	require.ErrorContains(t, err, "last port of your range(70000)")
}
