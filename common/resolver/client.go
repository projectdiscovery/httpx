package dns

import (
	"errors"
	"math/rand"
	"time"

	"github.com/miekg/dns"
)

const defaultPort = "53"

// Client dns instance
type Client struct {
	resolvers  []string
	maxRetries int
}

// Result containing ip and time to live
type Result struct {
	IPs []string
	TTL int
}

// New creates a new dns client
func New(baseResolvers []string, maxRetries int) (*Client, error) {
	rand.Seed(time.Now().UnixNano())
	client := Client{maxRetries: maxRetries}
	// fails on non unix systems so we just don't care
	resolvers, _ := ReadResolveConfig("/etc/resolv.conf")
	client.resolvers = append(client.resolvers, resolvers...)
	client.resolvers = append(client.resolvers, baseResolvers...)
	return &client, nil
}

// Resolve ips for a record
func (c *Client) Resolve(host string) (Result, error) {
	msg := new(dns.Msg)
	msg.Id = dns.Id()
	msg.RecursionDesired = true
	msg.Question = make([]dns.Question, 1)
	msg.Question[0] = dns.Question{
		Name:   dns.Fqdn(host),
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}
	resolver := c.resolvers[rand.Intn(len(c.resolvers))]
	var err error
	var answer *dns.Msg
	result := Result{}
	for i := 0; i < c.maxRetries; i++ {
		answer, err = dns.Exchange(msg, resolver)
		if err != nil {
			continue
		}
		if answer != nil && answer.Rcode != dns.RcodeSuccess {
			return result, errors.New(dns.RcodeToString[answer.Rcode])
		}
		for _, record := range answer.Answer {
			if t, ok := record.(*dns.A); ok {
				result.IPs = append(result.IPs, t.A.String())
				result.TTL = int(t.Header().Ttl)
			}
		}
		return result, nil
	}

	return result, err
}
