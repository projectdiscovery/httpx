package httpx

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"time"
)

// IsSmugglable checks if the target endpoint is a virtual host
func (h *HTTPX) IsSmugglable(protocol string, host string, port int, method string, normalduration, timeout time.Duration) (issmuggable bool, err error) {
	conn, err := h.dial(protocol, host, port, timeout)
	if err != nil {
		return false, err
	}

	// CL.TE probe
	probeCLTE := h.timingprobeCLTE(method, host)
	_, timeCLTE, errCLTE := h.sendprobe(conn, probeCLTE)
	if timeCLTE > normalduration {
		return true, errCLTE
	}

	// TE.CL probe
	probeTECL := h.timingprobeTECL(method, host)
	_, timeTECL, errTECL := h.sendprobe(conn, probeTECL)
	if timeTECL > normalduration {
		return true, errTECL
	}

	return
}

func (h *HTTPX) dial(protocol string, host string, port int, timeout time.Duration) (io.ReadWriter, error) {
	target := fmt.Sprintf("%s:%d", host, port)
	if protocol == "https" {
		CACerts, err := x509.SystemCertPool()
		if err != nil {
			return nil, err
		}
		return tls.DialWithDialer(&net.Dialer{Timeout: h.Options.Timeout}, "tcp", target, &tls.Config{RootCAs: CACerts, InsecureSkipVerify: true})
	}

	dialer := net.Dialer{Timeout: timeout}
	return dialer.Dial("tcp", target)
}

func (h *HTTPX) sendprobe(conn io.ReadWriter, probe string) (string, time.Duration, error) {
	start := time.Now()
	fmt.Fprint(conn, probe)
	fmt.Fprint(conn, "\r\n")
	resp, err := ioutil.ReadAll(conn)
	elapsed := time.Since(start)
	if err != nil {
		return "", elapsed, err
	}

	return string(resp), elapsed, nil
}

// All the following probing tecniques are taken from https://portswigger.net/web-security/request-smuggling/finding

// CL.TE vulnerabilities using timing techniques -
func (h *HTTPX) timingprobeCLTE(method string, host string) string {
	customHeaders := headersToString(h.CustomHeaders)

	return fmt.Sprintf("%s / HTTP/1.1\n"+
		"Host: %s\n"+
		"Transfer-Encoding: chunked\n"+
		"Content-Length: %d\n"+
		"%s\n"+
		"\n"+
		"1\n"+
		"A\n"+
		"X",
		method, host, 4+len(customHeaders), customHeaders)
}

// TE.CL vulnerabilities using timing techniques - https://portswigger.net/web-security/request-smuggling/finding
func (h *HTTPX) timingprobeTECL(method string, host string) string {
	customHeaders := headersToString(h.CustomHeaders)

	return fmt.Sprintf("%s / HTTP/1.1\n"+
		"Host: %s\n"+
		"Transfer-Encoding: chunked\n"+
		"Content-Length: %d\n"+
		"%s\n"+
		"\n"+
		"0\n"+
		"\n"+
		"\n"+
		"X",
		method, host, 6+len(customHeaders), customHeaders)
}

// CL.TE vulnerabilities using differential responses - https://portswigger.net/web-security/request-smuggling/finding
func (h *HTTPX) differentialprobeCLTE(method string, host string) string {
	return "todo"
}

// TE.CL vulnerabilities using differential responses - https://portswigger.net/web-security/request-smuggling/finding
func (h *HTTPX) differentialprobeTECL(method string, host string) string {
	return "todo"
}

func headersToString(headers map[string]string) (rawheaders string) {
	for name, value := range headers {
		rawheaders += fmt.Sprintf("%s: %s", name, value)
	}

	return rawheaders
}
