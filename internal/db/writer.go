package db

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx/runner"
)

type Writer struct {
	db       Database
	cfg      *Config
	data     chan runner.Result
	done     chan struct{}
	counter  atomic.Int64
	closed   atomic.Bool
	wg       sync.WaitGroup
	ctx      context.Context
	cancel   context.CancelFunc
	omitRaw  bool
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

	writerCtx, cancel := context.WithCancel(ctx)

	w := &Writer{
		db:      db,
		cfg:     cfg,
		data:    make(chan runner.Result, cfg.BatchSize),
		done:    make(chan struct{}),
		ctx:     writerCtx,
		cancel:  cancel,
		omitRaw: cfg.OmitRaw,
	}

	w.wg.Add(1)
	go w.run()

	gologger.Info().Msgf("Database output enabled: %s (%s/%s)", cfg.Type, cfg.DatabaseName, cfg.TableName)

	return w, nil
}

func (w *Writer) GetWriterCallback() runner.OnResultCallback {
	return func(r runner.Result) {
		if r.Err != nil {
			return
		}

		if w.omitRaw {
			r.Raw = ""
			r.Request = ""
			r.ResponseBody = ""
		}

		select {
		case w.data <- r:
		case <-w.ctx.Done():
		}
	}
}

func (w *Writer) run() {
	defer w.wg.Done()
	defer close(w.done)

	batch := make([]runner.Result, 0, w.cfg.BatchSize)
	ticker := time.NewTicker(w.cfg.FlushInterval)
	defer ticker.Stop()

	flush := func() {
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

		batch = batch[:0]
	}

	for {
		select {
		case <-w.ctx.Done():
			flush()
			return

		case <-ticker.C:
			flush()

		case result, ok := <-w.data:
			if !ok {
				flush()
				return
			}

			batch = append(batch, result)

			if len(batch) >= w.cfg.BatchSize {
				flush()
			}
		}
	}
}

func (w *Writer) Close() {
	if !w.closed.CompareAndSwap(false, true) {
		return
	}

	w.cancel()
	close(w.data)
	<-w.done

	if err := w.db.Close(); err != nil {
		gologger.Error().Msgf("Error closing database connection: %v", err)
	}

	gologger.Info().Msgf("Database writer closed. Total results stored: %d", w.counter.Load())
}

func (w *Writer) Stats() int64 {
	return w.counter.Load()
}
