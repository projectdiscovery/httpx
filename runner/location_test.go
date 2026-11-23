package runner

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// -location used to keep only the part of the header before the first ";".
func TestLocationKeepsSemicolons(t *testing.T) {
	const location = "/app/login;jsessionid=ABC123?next=/home"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", location)
		w.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	var (
		mu      sync.Mutex
		results []Result
	)
	options := &Options{
		Threads:   1,
		RateLimit: 10,
		Retries:   0,
		Timeout:   5,
		Methods:   http.MethodGet,
		Delay:     -1,
		Location:  true,
		NoColor:   true,
		OnResult: func(r Result) {
			if r.Err != nil || r.URL == "" {
				return
			}
			mu.Lock()
			results = append(results, r)
			mu.Unlock()
		},
		InputTargetHost: []string{srv.URL},
	}

	r, err := New(options)
	require.NoError(t, err)
	defer r.Close()
	r.RunEnumeration()

	mu.Lock()
	defer mu.Unlock()

	require.Len(t, results, 1)
	require.Equal(t, location, results[0].Location)
	require.Contains(t, results[0].str, "["+location+"]")
}
