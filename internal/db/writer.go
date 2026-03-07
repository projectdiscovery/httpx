package db

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx/runner"
	"github.com/projectdiscovery/utils/batcher"
)

type Writer struct {
	db      Database
	cfg     *Config
	batcher *batcher.Batcher[runner.Result]
	counter atomic.Int64
	closed  atomic.Bool
	omitRaw bool
}

func NewWriter(ctx context.Context, cfg *Config) (*Writer, error) {
	db, err := NewDatabase(cfg)
	if err != nil {
		return nil, err
	}

	if err := db.Connect(ctx); err != nil {
		return nil, err
	}

	if err := db.EnsureSchema(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}

	w := &Writer{
		db:      db,
		cfg:     cfg,
		omitRaw: cfg.OmitRaw,
	}

	w.batcher = batcher.New(
		batcher.WithMaxCapacity[runner.Result](cfg.BatchSize),
		batcher.WithFlushInterval[runner.Result](cfg.FlushInterval),
		batcher.WithFlushCallback(w.flush),
	)

	w.batcher.Run()

	gologger.Info().Msgf("Database output enabled: %s (%s/%s)", cfg.Type, cfg.DatabaseName, cfg.TableName)

	return w, nil
}

func (w *Writer) flush(batch []runner.Result) {
	if len(batch) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := w.db.InsertBatch(ctx, batch); err != nil {
		gologger.Error().Msgf("Failed to insert batch to database: %v", err)
	} else {
		w.counter.Add(int64(len(batch)))
		gologger.Verbose().Msgf("Inserted %d results to database (total: %d)", len(batch), w.counter.Load())
	}
}

func (w *Writer) GetWriterCallback() runner.OnResultCallback {
	return func(r runner.Result) {
		if w.closed.Load() {
			return
		}

		if r.Err != nil {
			return
		}

		if w.omitRaw {
			r.Raw = ""
			r.Request = ""
			r.ResponseBody = ""
			r.RawHeaders = ""
		}

		w.batcher.Append(r)
	}
}

func (w *Writer) Close() {
	if !w.closed.CompareAndSwap(false, true) {
		return
	}

	w.batcher.Stop()
	w.batcher.WaitDone()

	if err := w.db.Close(); err != nil {
		gologger.Error().Msgf("Error closing database connection: %v", err)
	}

	gologger.Info().Msgf("Database writer closed. Total results stored: %d", w.counter.Load())
}

func (w *Writer) Stats() int64 {
	return w.counter.Load()
}
