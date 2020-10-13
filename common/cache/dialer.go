package cache

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/coocood/freecache"
	dns "github.com/projectdiscovery/httpx/common/resolve"
)

var (
	dialerHistory *freecache.Cache
	cache         *Cache
)

// NoAddressFoundError occurs when no addresses are found for the host
type NoAddressFoundError struct{}

func (m *NoAddressFoundError) Error() string {
	return "no address found for host"
}

// DialerFunc with signature matching of go net/dial
type DialerFunc func(context.Context, string, string) (net.Conn, error)

// NewDialer gets a new Dialer instance using a resolver cache
func NewDialer(options Options) (DialerFunc, error) {
	if cache == nil {
		var err error
		cache, err = New(options)
		if err != nil {
			return nil, err
		}
		dialerHistory = freecache.NewCache(options.CacheSize * megaByteBytes)
	}

	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 10 * time.Second,
		DualStack: true,
	}
	return func(ctx context.Context, network, address string) (conn net.Conn, err error) {
		separator := strings.LastIndex(address, ":")

		// we need to filter out empty records
		hostname := address[:separator]
		dnsResult, err := cache.Lookup(hostname)
		if err != nil || len(dnsResult.IP4s)+len(dnsResult.IP6s) == 0 {
			return nil, &NoAddressFoundError{}
		}

		// Dial to the IPs finally.
		for _, ip := range append(dnsResult.IP4s, dnsResult.IP6s...) {
			conn, err = dialer.DialContext(ctx, network, ip+address[separator:])
			if err == nil {
				setErr := dialerHistory.Set([]byte(hostname), []byte(ip), 0)
				if setErr != nil {
					return nil, err
				}
				break
			}
		}
		return
	}, nil
}

// GetDialedIP returns the ip dialed by the HTTP client
func GetDialedIP(hostname string) string {
	v, err := dialerHistory.Get([]byte(hostname))
	if err != nil {
		return ""
	}
	return string(v)
}

// GetDNSData cached by the resolver
func GetDNSData(hostname string) (*dns.Result, error) {
	return cache.Lookup(hostname)
}
