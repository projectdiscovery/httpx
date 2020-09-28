package cache

import (
	"net"

	"github.com/coocood/freecache"
	dns "github.com/projectdiscovery/httpx/common/resolve"
)

const megaByteBytes = 1048576

// Cache is a structure for caching DNS lookups
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
	cache := freecache.NewCache(options.CacheSize * megaByteBytes)
	return &Cache{dnsClient: dnsClient, cache: cache, defaultExpirationTime: options.ExpirationTime}, nil
}

// Lookup a hostname
func (c *Cache) Lookup(hostname string) (*dns.Result, error) {
	if ip := net.ParseIP(hostname); ip != nil {
		return &dns.Result{IPs: []string{hostname}}, nil
	}
	hostnameBytes := []byte(hostname)
	value, err := c.cache.Get(hostnameBytes)
	if err != nil {
		// continue only if the failure is caused by cache-miss
		if err != freecache.ErrNotFound {
			return nil, err
		}
		result, resolveErr := c.dnsClient.Resolve(hostname)
		if resolveErr != nil {
			return nil, resolveErr
		}
		if result.TTL == 0 {
			result.TTL = c.defaultExpirationTime
		}
		b, _ := result.Marshal()

		err = c.cache.Set(hostnameBytes, b, result.TTL)
		if err != nil {
			return nil, err
		}

		return &result, nil
	}

	var result dns.Result

	err = result.Unmarshal(value)
	if err != nil {
		return nil, err
	}

	return &result, nil
}
