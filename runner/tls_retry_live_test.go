package runner

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// startTLSOnlyListener serves content over TLS and answers any plaintext
// request the way a real TLS listener does: a valid HTTP 400 saying TLS is
// required. The response is a successful HTTP transaction, which is what stops
// the transport-error scheme retry from firing.
func startTLSOnlyListener(t *testing.T) string {
	t.Helper()

	const rejection = "HTTP/1.1 400 Bad Request\r\n" +
		"Connection: close\r\n" +
		"Content-Type: text/plain;charset=utf-8\r\n" +
		"Content-Length: 62\r\n\r\n" +
		"Bad Request\r\nThis combination of host and port requires TLS.\r\n"

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "tls-only.test"},
		DNSNames:     []string{"localhost", "tls-only.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	require.NoError(t, err)

	tlsConfig := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html><head><title>Only Over TLS</title></head><body>ok</body></html>")
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				buffered := bufio.NewReader(conn)
				first, err := buffered.Peek(1)
				if err != nil {
					_ = conn.Close()
					return
				}
				// 0x16 is a TLS handshake record; anything else is plaintext.
				if first[0] != 0x16 {
					_, _ = io.WriteString(conn, rejection)
					_ = conn.Close()
					return
				}
				server.Serve(oneShot(tls.Server(&peeked{Conn: conn, reader: buffered}, tlsConfig)))
			}(conn)
		}
	}()

	return listener.Addr().String()
}

type peeked struct {
	net.Conn
	reader *bufio.Reader
}

func (c *peeked) Read(b []byte) (int, error) { return c.reader.Read(b) }

type oneShotListener struct {
	conn net.Conn
	used bool
}

func oneShot(conn net.Conn) net.Listener { return &oneShotListener{conn: conn} }

func (l *oneShotListener) Accept() (net.Conn, error) {
	if l.used {
		return nil, io.EOF
	}
	l.used = true
	return l.conn, nil
}
func (l *oneShotListener) Close() error   { return nil }
func (l *oneShotListener) Addr() net.Addr { return l.conn.LocalAddr() }

// TestTLSOnlyPortIsProbedOverHTTPS covers a TLS-only service on a port above
// 1024, which the scheme heuristic probes as plain HTTP first. Without the
// retry on a TLS-required response the service is reported as plain http.
func TestTLSOnlyPortIsProbedOverHTTPS(t *testing.T) {
	target := startTLSOnlyListener(t)

	var (
		mu      sync.Mutex
		results []Result
	)

	options := &Options{
		Threads:   1,
		RateLimit: 10,
		Retries:   0,
		Timeout:   5,
		Methods:   http.MethodGet,
		Delay:     -1,
		OnResult: func(r Result) {
			if r.Err != nil || r.URL == "" {
				return
			}
			mu.Lock()
			results = append(results, r)
			mu.Unlock()
		},
		InputTargetHost: []string{target},
	}

	// The heuristic must pick http first, otherwise this test proves nothing.
	require.Equal(t, "http", determineMostLikelySchemeOrder(target))

	r, err := New(options)
	require.NoError(t, err)
	defer r.Close()
	r.RunEnumeration()

	mu.Lock()
	defer mu.Unlock()

	require.Len(t, results, 1)
	require.Equal(t, "https", results[0].Scheme)
	require.Equal(t, "https://"+target, results[0].URL)
	require.Equal(t, http.StatusOK, results[0].StatusCode)
}
