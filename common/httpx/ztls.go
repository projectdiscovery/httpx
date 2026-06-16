package httpx

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/fastdialer/fastdialer/ja3/impersonate"
)

// newZTLSTransport builds the net/http transport used only for the ZTLS
// (-ztls) request path. reqx does not yet implement the lenient zcrypto/ztls
// handshake, so ZTLS requests keep using fastdialer's DialTLS (which performs
// the ztls handshake when the dialer is created WithZTLS). Every other request
// path uses reqx.
//
// This mirrors the historical httpx transport: it forces HTTP/1.1 (no automatic
// HTTP/2 upgrade), disables keep-alives and accepts any certificate. When
// -tls-impersonate is combined with -ztls, impersonation takes precedence for
// the handshake, matching the previous behavior.
func newZTLSTransport(dialer *fastdialer.Dialer, options *Options) (http.RoundTripper, error) {
	transport := &http.Transport{
		DialContext: dialer.Dial,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if options.TlsImpersonate {
				return dialer.DialTLSWithConfigImpersonate(ctx, network, addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}, impersonate.Random, nil)
			}
			return dialer.DialTLS(ctx, network, addr)
		},
		MaxIdleConnsPerHost: -1,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
		},
		DisableKeepAlives: true,
		// disable net/http's automatic HTTP/2 negotiation so the ztls path
		// stays on HTTP/1.1 (matching the reqx default path)
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
	}

	if options.SniName != "" {
		transport.TLSClientConfig.ServerName = options.SniName
	}

	if options.Proxy != "" {
		proxyURL, parseErr := url.Parse(options.Proxy)
		if parseErr != nil {
			return nil, parseErr
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	} else {
		transport.Proxy = http.ProxyFromEnvironment
	}

	return transport, nil
}
