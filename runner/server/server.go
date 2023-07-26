package server

import (
	"net/http"
	"strconv"

	"github.com/projectdiscovery/gologger"
)

// SetupServer sets up the server for webui
func SetupServer(addr string) (chan<- []byte, error) {
	var err error
	// Initialize the database
	db, err = NewHttpxDB("")
	if err != nil {
		return nil, err
	}
	http.HandleFunc("/count", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(strconv.Itoa(db.Count())))
	})

	// expected url format: /data?limit=10&cursor=1000
	http.HandleFunc("/data", func(w http.ResponseWriter, r *http.Request) {
		gologger.DefaultLogger.Print().Msgf("[%v] %v %v", r.RemoteAddr, r.Method, r.RequestURI)
		// Parse query parameters
		limit := r.URL.Query().Get("limit")
		cursor := r.URL.Query().Get("cursor")

		// Convert limit to integer
		n, err := strconv.Atoi(limit)
		if err != nil {
			http.Error(w, "Invalid limit", http.StatusBadRequest)
			return
		}

		// Call GetWithCursor
		buff, lastKey, err := db.GetWithCursor(n, cursor)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("x-cursor", lastKey)
		// Write the buffer content and the lastKey to the response
		w.Write(buff.Bytes())
	})

	go func() {
		if err := http.ListenAndServe(addr, nil); err != nil {
			gologger.Error().Msgf("Could not start webui server: %s\n", err)
		}
	}()
	return dBChan, nil
}

// Close closes the database
func Close() error {
	close(dBChan)
	return db.Close()
}

func Wait() {
	wg.Wait()
}
