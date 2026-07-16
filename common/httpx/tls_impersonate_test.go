package httpx

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/fastdialer/fastdialer/ja3/impersonate"
	"github.com/stretchr/testify/require"
)

// capturedHello holds the ClientHello details captured by the test TLS server.
type capturedHello struct {
	CipherSuites    []uint16
	SupportedCurves []tls.CurveID
	ServerName      string
	SupportedProtos []string
}

// startTLSServer creates a local TLS server that captures ClientHello info
// from each incoming connection. It returns the listener address and a function
// to retrieve the most recently captured hello.
func startTLSServer(t *testing.T) (string, func() *capturedHello) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}

	var mu sync.Mutex
	var latest *capturedHello

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			hello := &capturedHello{
				CipherSuites:    info.CipherSuites,
				SupportedCurves: info.SupportedCurves,
				ServerName:      info.ServerName,
				SupportedProtos: info.SupportedProtos,
			}
			mu.Lock()
			latest = hello
			mu.Unlock()
			return nil, nil
		},
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = ln.Close()
	})

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() {
					_ = conn.Close()
				}()
				buf := make([]byte, 1)
				_, _ = conn.Read(buf)
			}()
		}
	}()

	getHello := func() *capturedHello {
		mu.Lock()
		defer mu.Unlock()
		return latest
	}

	return ln.Addr().String(), getHello
}

// --- Unit tests for resolveImpersonateStrategy ---

func TestResolveImpersonateStrategy(t *testing.T) {
	t.Run("empty defaults to chrome", func(t *testing.T) {
		strategy, identity := resolveImpersonateStrategy("")
		require.Equal(t, impersonate.Chrome, strategy)
		require.Nil(t, identity)
	})

	t.Run("chrome", func(t *testing.T) {
		strategy, identity := resolveImpersonateStrategy("chrome")
		require.Equal(t, impersonate.Chrome, strategy)
		require.Nil(t, identity)
	})

	t.Run("chrome case insensitive", func(t *testing.T) {
		strategy, identity := resolveImpersonateStrategy("CHROME")
		require.Equal(t, impersonate.Chrome, strategy)
		require.Nil(t, identity)
	})

	t.Run("valid ja3 string", func(t *testing.T) {
		ja3str := "771,49195-49196,0-23-65281-10-11-35-16-5-13-18,23-24,0"
		strategy, identity := resolveImpersonateStrategy(ja3str)
		require.Equal(t, impersonate.Custom, strategy)
		require.NotNil(t, identity)
	})

	t.Run("random maps to chrome", func(t *testing.T) {
		strategy, identity := resolveImpersonateStrategy("random")
		require.Equal(t, impersonate.Chrome, strategy)
		require.Nil(t, identity)
	})

	t.Run("invalid ja3 falls back to chrome", func(t *testing.T) {
		strategy, identity := resolveImpersonateStrategy("not-a-ja3-string")
		require.Equal(t, impersonate.Chrome, strategy)
		require.Nil(t, identity)
	})

	t.Run("partial ja3 falls back to chrome", func(t *testing.T) {
		strategy, identity := resolveImpersonateStrategy("771,4865")
		require.Equal(t, impersonate.Chrome, strategy)
		require.Nil(t, identity)
	})
}

// Integration tests with local TLS server

func TestTLSImpersonate_DefaultGoTLS(t *testing.T) {
	addr, getHello := startTLSServer(t)

	opts := fastdialer.DefaultOptions
	opts.EnableFallback = false
	fd, err := fastdialer.NewDialer(opts)
	require.NoError(t, err)
	defer fd.Close()

	conn, err := fd.DialTLSWithConfigImpersonate(
		context.Background(), "tcp", addr,
		&tls.Config{InsecureSkipVerify: true},
		impersonate.None, nil,
	)
	require.NoError(t, err)
	_ = conn.Close()

	hello := getHello()
	require.NotNil(t, hello)
	require.NotEmpty(t, hello.CipherSuites, "default Go TLS should have cipher suites")
}

func TestTLSImpersonate_Chrome(t *testing.T) {
	addr, getHello := startTLSServer(t)

	opts := fastdialer.DefaultOptions
	opts.EnableFallback = false
	fd, err := fastdialer.NewDialer(opts)
	require.NoError(t, err)
	defer fd.Close()

	conn, err := fd.DialTLSWithConfigImpersonate(
		context.Background(), "tcp", addr,
		&tls.Config{InsecureSkipVerify: true},
		impersonate.Chrome, nil,
	)
	require.NoError(t, err)
	_ = conn.Close()

	hello := getHello()
	require.NotNil(t, hello)
	require.NotEmpty(t, hello.CipherSuites)
	hasGrease := false
	for _, cs := range hello.CipherSuites {
		if cs&0x0f0f == 0x0a0a {
			hasGrease = true
			break
		}
	}
	require.True(t, hasGrease, "Chrome impersonation should include GREASE cipher suite values")
}

func TestTLSImpersonate_CustomJA3(t *testing.T) {
	addr, getHello := startTLSServer(t)

	ja3Str := "771,49195-49196,0-23-65281-10-11-35-16-5-13-18,23-24,0"
	strategy, identity := resolveImpersonateStrategy(ja3Str)
	require.Equal(t, impersonate.Custom, strategy)
	require.NotNil(t, identity)

	opts := fastdialer.DefaultOptions
	opts.EnableFallback = false
	fd, err := fastdialer.NewDialer(opts)
	require.NoError(t, err)
	defer fd.Close()

	conn, err := fd.DialTLSWithConfigImpersonate(
		context.Background(), "tcp", addr,
		&tls.Config{InsecureSkipVerify: true},
		strategy, identity,
	)
	require.NoError(t, err)
	require.NotNil(t, conn)
	_ = conn.Close()

	hello := getHello()
	require.NotNil(t, hello)

	require.Equal(t, []uint16{49195, 49196}, hello.CipherSuites,
		"custom JA3 should contain exactly the specified cipher suites")

	expectedCurves := []tls.CurveID{23, 24}
	require.Equal(t, expectedCurves, hello.SupportedCurves,
		"custom JA3 should contain exactly the specified curves")
}

func TestTLSImpersonate_ChromeDiffersFromDefault(t *testing.T) {
	addr, getHello := startTLSServer(t)

	opts := fastdialer.DefaultOptions
	opts.EnableFallback = false
	fd, err := fastdialer.NewDialer(opts)
	require.NoError(t, err)
	defer fd.Close()

	conn, err := fd.DialTLSWithConfigImpersonate(
		context.Background(), "tcp", addr,
		&tls.Config{InsecureSkipVerify: true},
		impersonate.None, nil,
	)
	require.NoError(t, err)
	_ = conn.Close()
	defaultHello := getHello()

	conn, err = fd.DialTLSWithConfigImpersonate(
		context.Background(), "tcp", addr,
		&tls.Config{InsecureSkipVerify: true},
		impersonate.Chrome, nil,
	)
	require.NoError(t, err)
	_ = conn.Close()
	chromeHello := getHello()

	require.NotNil(t, defaultHello)
	require.NotNil(t, chromeHello)

	require.NotEqual(t, defaultHello.CipherSuites, chromeHello.CipherSuites,
		"Chrome impersonation should produce different cipher suites than default Go TLS")
}

func TestTLSImpersonate_CustomJA3DiffersFromDefault(t *testing.T) {
	addr, getHello := startTLSServer(t)

	opts := fastdialer.DefaultOptions
	opts.EnableFallback = false
	fd, err := fastdialer.NewDialer(opts)
	require.NoError(t, err)
	defer fd.Close()

	// Default (no impersonation)
	conn, err := fd.DialTLSWithConfigImpersonate(
		context.Background(), "tcp", addr,
		&tls.Config{InsecureSkipVerify: true},
		impersonate.None, nil,
	)
	require.NoError(t, err)
	_ = conn.Close()
	defaultHello := getHello()

	ja3Str := "771,49195-49196,0-23-65281-10-11-35-16-5-13-18,23-24,0"
	strategy, identity := resolveImpersonateStrategy(ja3Str)
	require.Equal(t, impersonate.Custom, strategy)

	conn, err = fd.DialTLSWithConfigImpersonate(
		context.Background(), "tcp", addr,
		&tls.Config{InsecureSkipVerify: true},
		strategy, identity,
	)
	require.NoError(t, err)
	_ = conn.Close()
	customHello := getHello()

	require.NotNil(t, defaultHello)
	require.NotNil(t, customHello)

	require.NotEqual(t, defaultHello.CipherSuites, customHello.CipherSuites,
		"custom JA3 should produce different cipher suites than default Go TLS")
}

func TestTLSImpersonate_EndToEnd_HTTPX(t *testing.T) {
	addr, getHello := startTLSServer(t)

	tests := []struct {
		name     string
		strategy string
		wantErr  bool
	}{
		{"disabled", "", false},
		{"chrome", "chrome", false},
		{"ja3", "771,49195-49196,0-23-65281-10-11-35-16-5-13-18,23-24,0", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := DefaultOptions
			options.TlsImpersonate = tt.strategy

			ht, err := New(&options)
			require.NoError(t, err)

			dialer := ht.buildTLSDialer(&options)
			conn, err := dialer(context.Background(), "tcp", addr)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, conn)
			_ = conn.Close()

			if tt.strategy != "" {
				hello := getHello()
				require.NotNil(t, hello)
				require.NotEmpty(t, hello.CipherSuites)
			}
		})
	}
}

func TestTLSImpersonate_EndToEnd_JA3(t *testing.T) {
	addr, getHello := startTLSServer(t)

	ja3Str := "771,49195-49196,0-23-65281-10-11-35-16-5-13-18,23-24,0"
	options := DefaultOptions
	options.TlsImpersonate = ja3Str

	ht, err := New(&options)
	require.NoError(t, err)

	dialer := ht.buildTLSDialer(&options)
	conn, err := dialer(context.Background(), "tcp", addr)
	require.NoError(t, err)
	require.NotNil(t, conn)
	_ = conn.Close()

	hello := getHello()
	require.NotNil(t, hello)

	require.Equal(t, []uint16{49195, 49196}, hello.CipherSuites,
		"JA3 end-to-end cipher suites should match exactly")
	require.Equal(t, []tls.CurveID{23, 24}, hello.SupportedCurves,
		"JA3 end-to-end curves should match exactly")
}
