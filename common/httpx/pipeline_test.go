package httpx

import (
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSupportPipelineClosesConn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)

	closed := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 64*1024)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
		_, _ = io.Copy(io.Discard, conn)
		close(closed)
	}()

	h := &HTTPX{}
	_ = h.SupportPipeline("http", "GET", "127.0.0.1", port)

	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("pipeline probe connection was not closed")
	}
}

func TestSupportPipelineDialError(t *testing.T) {
	h := &HTTPX{}
	require.False(t, h.SupportPipeline("http", "GET", "127.0.0.1", 1))
}
