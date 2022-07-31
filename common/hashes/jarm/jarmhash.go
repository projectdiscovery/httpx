package jarm

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/hdm/jarm-go"
	"github.com/projectdiscovery/fastdialer/fastdialer"
)

const defaultPort int = 443

type target struct {
	Host string
	Port int
}

// fingerprint probes a single host/port
func fingerprint(dialer *fastdialer.Dialer, t target, timeout time.Duration) string {
	results := []string{}
	addr := net.JoinHostPort(t.Host, fmt.Sprintf("%d", t.Port))
	// using connection pool as we need multiple probes
	pool, err := newOneTimePool(context.Background(), addr, 3)
	if err != nil {
		return ""
	}
	pool.FastDialer = dialer

	defer pool.Close() //nolint
	go pool.Run()      //nolint

	for _, probe := range jarm.GetProbes(t.Host, t.Port) {
		conn, err := pool.Acquire(context.Background())
		if err != nil {
			continue
		}
		if conn == nil {
			continue
		}
		_ = conn.SetWriteDeadline(time.Now().Add(timeout))
		_, err = conn.Write(jarm.BuildProbe(probe))
		if err != nil {
			results = append(results, "")
			_ = conn.Close()
			continue
		}
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		buff := make([]byte, 1484)
		_, _ = conn.Read(buff)
		_ = conn.Close()
		ans, err := jarm.ParseServerHello(buff, probe)
		if err != nil {
			results = append(results, "")
			continue
		}
		results = append(results, ans)
	}
	return jarm.RawHashToFuzzyHash(strings.Join(results, ","))
}

func Jarm(dialer *fastdialer.Dialer, host string, duration int) string {
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
	timeout := time.Duration(duration) * time.Second
	return fingerprint(dialer, t, timeout)
}
