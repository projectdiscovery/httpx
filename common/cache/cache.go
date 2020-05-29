package cache

import (
	"net"

	"github.com/coocood/freecache"
	dns "github.com/projectdiscovery/httpx/common/resolver"
)

// Cache is a strcture for caching DNS lookups
type Cache struct {
	dnsClient             Resolver
	cache                 *freecache.Cache
	defaultExpirationTime int
}

// Resolver interface
type Resolver interface {
	Resolve(string) (dns.Result, error)
}

// Options of the cache
type Options struct {
	BaseResolvers  []string
	CacheSize      int
	ExpirationTime int
	MaxRetries     int
}

// DefaultOptions of the cache
var DefaultOptions = Options{
	BaseResolvers:  DefaultResolvers,
	CacheSize:      10,
	ExpirationTime: 5 * 60,
	MaxRetries:     5,
}

// DefaultResolvers trusted
var DefaultResolvers = []string{
	"1.1.1.1:53",
	"1.0.0.1:53",
	"8.8.8.8:53",
	"8.8.4.4:53",
}

// New creates a new caching dns resolver
func New(options Options) (*Cache, error) {
	dnsClient, err := dns.New(options.BaseResolvers, options.MaxRetries)
	if err != nil {
		return nil, err
	}
	cache := freecache.NewCache(options.CacheSize * 1024 * 1024)
	return &Cache{dnsClient: dnsClient, cache: cache, defaultExpirationTime: options.ExpirationTime}, nil
}

// Lookup a hostname
func (c *Cache) Lookup(hostname string) ([]string, error) {
	if ip := net.ParseIP(hostname); ip != nil {
		return []string{hostname}, nil
	}
	hostnameBytes := []byte(hostname)
	value, err := c.cache.Get(hostnameBytes)
	if err != nil {
		if len(err.Error()) != 15 {
			return nil, err
		}
		results, err := c.dnsClient.Resolve(hostname)
		if err != nil {
			return nil, err
		}
		if results.TTL == 0 {
			results.TTL = c.defaultExpirationTime
		}
		c.cache.Set(hostnameBytes, MarshalAddresses(results.IPs), results.TTL)

		return results.IPs, nil
	}

	return UnmarshalAddresses(value), nil
}
