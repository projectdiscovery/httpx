package resolve

import (
	"bytes"
	"encoding/gob"
	"errors"
	"math/rand"
	"strings"
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
	IPs    []string
	CNAMEs []string
	TTL    int
}

// Marshal structure to bytes
func (r *Result) Marshal() ([]byte, error) {
	var b bytes.Buffer
	enc := gob.NewEncoder(&b)
	err := enc.Encode(r)
	if err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

// Unmarshal structure
func (r *Result) Unmarshal(b []byte) error {
	dec := gob.NewDecoder(bytes.NewBuffer(b))
	err := dec.Decode(&r)
	if err != nil {
		return err
	}
	return nil
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
			switch t := record.(type) {
			case *dns.A:
				ip := t.A.String()
				if ip != "" {
					result.IPs = append(result.IPs, t.A.String())
					result.TTL = int(t.Header().Ttl)
				}
			case *dns.CNAME:
				if t.Target != "" {
					result.CNAMEs = append(result.CNAMEs, strings.TrimSuffix(t.Target, "."))
				}
			}
		}
		return result, nil
	}

	return result, err
}
