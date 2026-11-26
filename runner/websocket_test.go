package runner

import (
	"testing"

	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/stretchr/testify/require"
)

func TestIsWebSocket(t *testing.T) {
	for _, tc := range []struct {
		name string
		resp httpx.Response
		want bool
	}{
		{"switching protocols", httpx.Response{StatusCode: 101}, true},
		{"upgrade required", httpx.Response{StatusCode: 426, RawHeaders: "HTTP/1.1 426 Upgrade Required\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"}, true},
		{"lowercase header", httpx.Response{StatusCode: 400, RawHeaders: "HTTP/1.1 400 Bad Request\r\nupgrade: WebSocket\r\n"}, true},
		{"protocol list", httpx.Response{StatusCode: 426, RawHeaders: "HTTP/1.1 426 Upgrade Required\r\nUpgrade: h2c, websocket\r\n"}, true},
		{"accept header", httpx.Response{StatusCode: 200, RawHeaders: "HTTP/1.1 200 OK\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"}, true},
		{"h2c upgrade offer", httpx.Response{StatusCode: 200, RawHeaders: "HTTP/1.1 200 OK\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n"}, false},
		{"other protocol name", httpx.Response{StatusCode: 426, RawHeaders: "HTTP/1.1 426 Upgrade Required\r\nUpgrade: websocket-other\r\n"}, false},
		{"empty accept header", httpx.Response{StatusCode: 200, RawHeaders: "HTTP/1.1 200 OK\r\nSec-WebSocket-Accept:\r\nServer: x\r\n"}, false},
		{"socket.io handshake", httpx.Response{StatusCode: 200, RawHeaders: "HTTP/1.1 200 OK\r\n", RawData: []byte(`{"sid":"abc","upgrades":["websocket"],"pingInterval":25000}`)}, true},
		{"plain page", httpx.Response{StatusCode: 200, RawHeaders: "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n", RawData: []byte("<html></html>")}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, isWebSocket(&tc.resp))
		})
	}
}
