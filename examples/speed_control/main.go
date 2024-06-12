package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/httpx/runner"
)

func main() {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose) // increase the verbosity (optional)

	// generate urls
	var urls []string
	for i := 0; i < 100; i++ {
		urls = append(urls, fmt.Sprintf("https://scanme.sh/a=%d", i))
	}

	apiEndpoint := "127.0.0.1:31234"

	options := runner.Options{
		Methods:         "GET",
		InputTargetHost: goflags.StringSlice(urls),
		Threads:         1,
		HttpApiEndpoint: apiEndpoint,
		OnResult: func(r runner.Result) {
			// handle error
			if r.Err != nil {
				fmt.Printf("[Err] %s: %s\n", r.Input, r.Err)
				return
			}
			fmt.Printf("%s %s %d\n", r.Input, r.Host, r.StatusCode)
		},
	}

	// after 3 seconds increase the speed to 50
	time.AfterFunc(3*time.Second, func() {
		client := &http.Client{}

		concurrencySettings := runner.Concurrency{Threads: 50}
		requestBody, err := json.Marshal(concurrencySettings)
		if err != nil {
			log.Fatalf("Error creating request body: %v", err)
		}

		req, err := http.NewRequest("PUT", fmt.Sprintf("http://%s/api/concurrency", apiEndpoint), bytes.NewBuffer(requestBody))
		if err != nil {
			log.Fatalf("Error creating PUT request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			log.Fatalf("Error sending PUT request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			log.Printf("Failed to update threads, status code: %d", resp.StatusCode)
		} else {
			log.Println("Threads updated to 50 successfully")
		}
	})

	if err := options.ValidateOptions(); err != nil {
		log.Fatal(err)
	}

	httpxRunner, err := runner.New(&options)
	if err != nil {
		log.Fatal(err)
	}
	defer httpxRunner.Close()

	httpxRunner.RunEnumeration()

	// check the threads
	req, err := http.Get(fmt.Sprintf("http://%s/api/concurrency", apiEndpoint))
	if err != nil {
		log.Fatalf("Error creating GET request: %v", err)
	}
	var concurrencySettings runner.Concurrency
	if err := json.NewDecoder(req.Body).Decode(&concurrencySettings); err != nil {
		log.Fatalf("Error decoding response body: %v", err)
	}

	if concurrencySettings.Threads == 50 {
		log.Println("Threads are set to 50")
	} else {
		log.Fatalf("Fatal error: Threads are not set to 50, current value: %d", concurrencySettings.Threads)
	}
}
