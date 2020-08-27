package cache

import (
	"context"
	"net"
	"strings"
	"time"
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
	cache, err := New(options)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 10 * time.Second,
		DualStack: true,
	}
	return func(ctx context.Context, network, address string) (conn net.Conn, err error) {
		separator := strings.LastIndex(address, ":")

		// we need to filter out empty records
		ips, err := cache.Lookup(address[:separator])
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
				break
			}
		}
		return
	}, nil
}
