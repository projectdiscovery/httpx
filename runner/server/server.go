package server

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/projectdiscovery/gologger"
)

// SetupServer sets up the server for webui
func SetupServer(addr string) (chan<- []byte, error) {
	var err error
	// Initialize the database
	db, err = newHttpxDB()
	if err != nil {
		return nil, err
	}
	http.HandleFunc("/count", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(strconv.Itoa(db.Count())))
	})

	// expected url format: /data?index=1
	http.HandleFunc("/data", func(w http.ResponseWriter, r *http.Request) {
		index := r.URL.Query().Get("index")
		val, err := strconv.Atoi(index)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "invalid data index : %v error: %v", index, err)
			return
		}
		data, ok := db.Get(strconv.Itoa(val))
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "invalid data index : %v", index)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write(data)
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
