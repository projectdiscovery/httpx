package server

import (
	"context"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/hmap/store/hybrid"
)

var (
	db     *httpxDB
	wg     *sync.WaitGroup = &sync.WaitGroup{}
	dBChan                 = make(chan []byte, 100)
)

type httpxDB struct {
	hm      *hybrid.HybridMap
	counter atomic.Int32
	cancel  context.CancelFunc
}

// Get returns the value of a key
func (h *httpxDB) Get(key string) ([]byte, bool) {
	if intVal, _ := strconv.Atoi(key); intVal < 0 || key == "" {
		return []byte{}, false
	}
	v, ok := h.hm.Get(key)
	return v, ok
}

// Set sets
func (h *httpxDB) Set(value []byte) error {
	return h.hm.Set(string(h.counter.Add(1)), value)
}

// Count returns the number of entries in the database
func (h *httpxDB) Count() int {
	return int(h.counter.Load())
}

// Close closes the database
func (h *httpxDB) Close() error {
	h.cancel()
	return h.hm.Close()
}

// Worker is the worker for the database
func (h *httpxDB) Worker(ctx context.Context) {
	defer wg.Done()
	for {
		select {
		case data, ok := <-dBChan:
			if !ok {
				return
			}
			err := h.Set(data)
			if err != nil {
				gologger.Error().Msgf("Could not save data to db: %s\n", err)
			}
		case <-ctx.Done():
			return
		}
	}
}

func newHttpxDB() (*httpxDB, error) {
	hm, err := hybrid.New(hybrid.DefaultHybridOptions)
	if err != nil {
		return &httpxDB{}, err
	}
	h := &httpxDB{
		hm:      hm,
		counter: atomic.Int32{},
	}
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	wg.Add(1)
	go h.Worker(ctx)
	return h, nil
}
