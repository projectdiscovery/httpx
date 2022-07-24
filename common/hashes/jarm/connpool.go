package jarm

import (
	"net"
	"sync"

	"go.uber.org/multierr"
)

type inFlightConns struct {
	sync.RWMutex
	inflightConns map[net.Conn]struct{}
}

func newInFlightConns() (*inFlightConns, error) {
	return &inFlightConns{inflightConns: make(map[net.Conn]struct{})}, nil
}

func (i *inFlightConns) Add(conn net.Conn) {
	i.Lock()
	defer i.Unlock()

	i.inflightConns[conn] = struct{}{}
}

func (i *inFlightConns) Remove(conn net.Conn) {
	i.Lock()
	defer i.Unlock()

	delete(i.inflightConns, conn)
}

func (i *inFlightConns) Close() error {
	i.Lock()
	defer i.Unlock()

	var errs []error

	for conn := range i.inflightConns {
		if err := conn.Close(); err != nil {
			errs = append(errs, err)
		}
		delete(i.inflightConns, conn)
	}

	return multierr.Combine(errs...)
}
