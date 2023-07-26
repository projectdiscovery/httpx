package server

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/projectdiscovery/gologger"
	"go.etcd.io/bbolt"
)

var (
	db         *httpxDB
	wg         *sync.WaitGroup = &sync.WaitGroup{}
	dBChan                     = make(chan []byte, 100)
	indexStart                 = 1000  // start index for data
	Persist                    = false // whether to persist data to disk
	bucketName                 = []byte("jsonl")
)

type httpxDB struct {
	bb      *bbolt.DB
	dbPath  string
	counter atomic.Int32
	cancel  context.CancelFunc
}

// Set stores a value in the database by incrementing counter
func (h *httpxDB) Set(value []byte) error {
	index := strconv.Itoa(int(h.counter.Add(1)))
	err := h.bb.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketName)
		if bucket == nil {
			var err error
			bucket, err = tx.CreateBucket(bucketName)
			if err != nil {
				return err
			}
		}
		return bucket.Put([]byte(index), value)
	})
	return err
}

// Get retrieves a value from database given a key
func (h *httpxDB) Get(key string) ([]byte, error) {
	var value []byte
	err := h.bb.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketName)
		if bucket == nil {
			return fmt.Errorf("bucket not found")
		}
		value = bucket.Get([]byte(key))
		return nil
	})
	return value, err
}

// GetWithCursor retrieves n values from database starting from cursor
func (h *httpxDB) GetWithCursor(n int, cursor string) (*bytes.Buffer, string, error) {
	var buff bytes.Buffer
	var lastKey string
	err := h.bb.View(func(tx *bbolt.Tx) error {
		bkt := tx.Bucket([]byte(bucketName))
		if bkt == nil {
			return bbolt.ErrBucketNotFound
		}
		c := bkt.Cursor()

		var k, v []byte
		if cursor == "" {
			k, v = c.First() // First item in the bucket
		} else {
			k, v = c.Seek([]byte(cursor)) // Start the cursor from the provided key
			if k == nil {
				// in case of a bad cursor, return error
				return fmt.Errorf("invalid cursor %v", cursor)
			} else {
				if bytes.Equal(k, []byte(cursor)) {
					k, v = c.Next() // Only move to next key if we found the exact match of the cursor
				}
			}
		}

		count := 0
		for ; k != nil && count < n; k, v = c.Next() {
			lastKey = string(k) // store the last key read
			buff.Write(v)
			buff.WriteString("\n")
			count++
		}
		return nil
	})
	return &buff, lastKey, err // return the last key read as cursor
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

// Count returns the number of entries in the database
func (h *httpxDB) Count() int {
	var count int
	_ = h.bb.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketName)
		if bucket == nil {
			return nil
		}
		count = bucket.Stats().KeyN
		return nil
	})
	return count
}

// Close closes the database
func (h *httpxDB) Close() error {
	h.cancel()
	return os.RemoveAll(filepath.Dir(h.dbPath))
}

// NewHttpxDB opens a new bbolt database at given dbpath. If no path is given, it uses a temporary path.
func NewHttpxDB(dbpath string) (*httpxDB, error) {
	if dbpath == "" {
		dirpath, _ := os.MkdirTemp(os.TempDir(), "httpx")
		dbpath = filepath.Join(dirpath, "httpx.db")
	}
	bb, err := bbolt.Open(dbpath, 0600, nil)
	if err != nil {
		return nil, err
	}
	h := &httpxDB{
		bb:      bb,
		counter: atomic.Int32{},
		dbPath:  dbpath,
	}
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	h.counter.Store(int32(indexStart))
	wg.Add(1)
	go h.Worker(ctx)
	return h, nil
}
