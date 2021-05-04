package httpx

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// SupportPipeline checks if the target host supports HTTP1.1 pipelining by sending x probes
// and reading back responses expecting at least 2 with HTTP/1.1 or HTTP/1.0
func (h *HTTPX) SupportPipeline(protocol, method, host string, port int) bool {
	addr := host
	if port == 0 {
		port = 80
		if protocol == "https" {
			port = 443
		}
	}
	if port > 0 {
		addr = fmt.Sprintf("%s:%d", host, port)
	}
	// dummy method while awaiting for full rawhttp implementation
	dummyReq := fmt.Sprintf("%s / HTTP/1.1\nHost: %s\n\n", method, addr)
	conn, err := pipelineDial(protocol, addr)
	if err != nil {
		return false
	}
	// send some probes
	nprobes := 10
	for i := 0; i < nprobes; i++ {
		if _, err = conn.Write([]byte(dummyReq)); err != nil {
			return false
		}
	}
	gotReplies := 0
	reply := make([]byte, 1024)
	for i := 0; i < nprobes; i++ {
		err := conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		if err != nil {
			return false
		}

		if _, err := conn.Read(reply); err != nil {
			break
		}

		// The check is very naive, but it works most of the times
		for _, s := range strings.Split(string(reply), "\n\n") {
			if strings.Contains(s, "HTTP/1.1") || strings.Contains(s, "HTTP/1.0") {
				gotReplies++
			}
		}
	}

	// expect at least 2 replies
	return gotReplies >= 2 //nolint
}

func pipelineDial(protocol, addr string) (net.Conn, error) {
	// http
	if protocol == "http" {
		return net.Dial("tcp", addr)
	}

	// https
	return tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
}
