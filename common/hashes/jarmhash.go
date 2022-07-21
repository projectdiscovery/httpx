package hashes

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/hdm/jarm-go"
	"golang.org/x/net/proxy"
)

const defaultPort int = 443

var DefualtBackoff = func(r, m int) time.Duration {
	return time.Second
}

type target struct {
	Host    string
	Port    int
	Retries int
	Backoff func(r, m int) time.Duration
}

// fingerprint probes a single host/port
func fingerprint(t target, duration int) string {
	timeout := time.Duration(duration) * time.Second
	results := []string{}
	for _, probe := range jarm.GetProbes(t.Host, t.Port) {
		dialer := proxy.FromEnvironmentUsing(&net.Dialer{Timeout: timeout})
		addr := net.JoinHostPort(t.Host, fmt.Sprintf("%d", t.Port))
		c := net.Conn(nil)
		n := 0
		for c == nil && n <= t.Retries {
			// Ignoring error since error message was already being dropped.
			// Also, if theres an error, c == nil.
			if c, _ = dialer.Dial("tcp", addr); c != nil || t.Retries == 0 {
				break
			}
			bo := t.Backoff
			if bo == nil {
				bo = DefualtBackoff
			}
			time.Sleep(bo(n, t.Retries))
			n++
		}
		if c == nil {
			return ""
		}
		data := jarm.BuildProbe(probe)
		_ = c.SetWriteDeadline(time.Now().Add(timeout))
		_, err := c.Write(data)
		if err != nil {
			results = append(results, "")
			c.Close()
			continue
		}
		_ = c.SetReadDeadline(time.Now().Add(timeout))
		buff := make([]byte, 1484)
		_, _ = c.Read(buff)
		c.Close()
		ans, err := jarm.ParseServerHello(buff, probe)
		if err != nil {
			results = append(results, "")
			continue
		}
		results = append(results, ans)
	}
	return jarm.RawHashToFuzzyHash(strings.Join(results, ","))
}
func Jarm(host string, duration int) string {
	t := target{}
	if u, err := url.Parse(host); err == nil {
		if u.Scheme == "http" {
			return ""
		}
		t.Host = u.Hostname()
		port, _ := strconv.Atoi(u.Port())
		t.Port = port
	}
	if t.Port == 0 {
		t.Port = defaultPort
	}
	return fingerprint(t, duration)
}
