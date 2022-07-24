package jarm

import (
	"context"
	"net"

	"github.com/projectdiscovery/fastdialer/fastdialer"
)

// oneTimePool is a pool designed to create continous bare connections that are for one time only usage
type oneTimePool struct {
	address         string
	idleConnections chan net.Conn
	InFlightConns   *inFlightConns
	ctx             context.Context
	cancel          context.CancelFunc
	FastDialer      *fastdialer.Dialer
}

func newOneTimePool(ctx context.Context, address string, poolSize int) (*oneTimePool, error) {
	idleConnections := make(chan net.Conn, poolSize)
	inFlightConns, err := newInFlightConns()
	if err != nil {
		return nil, err
	}
	pool := &oneTimePool{
		address:         address,
		idleConnections: idleConnections,
		InFlightConns:   inFlightConns,
	}
	if ctx != nil {
		pool.ctx = ctx
	}
	pool.ctx, pool.cancel = context.WithCancel(ctx)
	return pool, nil
}

// Acquire acquires an idle connection from the pool
func (p *oneTimePool) Acquire(c context.Context) (net.Conn, error) {
	select {
	case <-p.ctx.Done():
		return nil, p.ctx.Err()
	case <-c.Done():
		return nil, c.Err()
	case conn := <-p.idleConnections:
		p.InFlightConns.Remove(conn)
		return conn, nil
	}
}

func (p *oneTimePool) Run() error {
	for {
		select {
		case <-p.ctx.Done():
			return p.ctx.Err()
		default:
			var (
				conn net.Conn
				err  error
			)
			if p.FastDialer != nil {
				conn, err = p.FastDialer.Dial(p.ctx, "tcp", p.address)
			} else {
				conn, err = net.Dial("tcp", p.address)
			}
			if err == nil {
				p.InFlightConns.Add(conn)
				p.idleConnections <- conn
			}
		}
	}
}

func (p *oneTimePool) Close() error {
	p.cancel()
	return p.InFlightConns.Close()
}
