package cache

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/coocood/freecache"
)

var dialerHistory *freecache.Cache

// NoAddressFoundError occurs when no addresses are found for the host
type NoAddressFoundError struct{}

func (m *NoAddressFoundError) Error() string {
	return "no address found for host"
}

// DialerFunc with signature matching of go net/dial
type DialerFunc func(context.Context, string, string) (net.Conn, error)

// NewDialer gets a new Dialer instance using a resolver cache
func NewDialer(options Options) (DialerFunc, error) {
	cache, err := New(options)
	if err != nil {
		return nil, err
	}
	dialerHistory = freecache.NewCache(options.CacheSize * 1024 * 1024)
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 10 * time.Second,
		DualStack: true,
	}
	return func(ctx context.Context, network, address string) (conn net.Conn, err error) {
		separator := strings.LastIndex(address, ":")

		// we need to filter out empty records
		hostname := address[:separator]
		ips, err := cache.Lookup(hostname)
		var finalIps []string
		for _, ip := range ips {
			if ip != "" {
				finalIps = append(finalIps, ip)
			}
		}
		if err != nil || len(finalIps) == 0 {
			return nil, &NoAddressFoundError{}
		} // Dial to the IPs finally.
		for _, ip := range ips {
			conn, err = dialer.DialContext(ctx, network, ip+address[separator:])
			if err == nil {
				dialerHistory.Set([]byte(hostname), []byte(ip), 0)
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
