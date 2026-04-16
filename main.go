package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

type MonitorSites struct {
	Sites []Site `json:"sites"`
}

type Site struct {
	ID             string                 `json:"id"`
	Name           string                 `json:"name"`
	Url            string                 `json:"url"`
	Method         string                 `json:"method"`
	ExpectedStatus int                    `json:"expected_status"`
	Timeout        int                    `json:"timeout_ms"`
	ExpectedResult map[string]interface{} `json:"expected_result"`
}

func main() {
	log.Print("Stating Service")
	killChan := make(chan os.Signal, 1)
	signal.Notify(killChan, syscall.SIGINT, syscall.SIGTERM)
	var wg sync.WaitGroup
	interval := flag.Int("interval", 5, "Interval between checks in seconds")

	log.Print("Looking for targets.json file")
	targets, err := os.Open("target.json")
	if err != nil {
		log.Fatalf("Error with opening targets.json: %v", err)
	}
	defer targets.Close()

	byteVal, err := io.ReadAll(targets)
	if err != nil {
		log.Fatalf("Error converting target into bytes: %e", err)
	}

	log.Print("Unpacking the json file")
	var Msites MonitorSites
	err = json.Unmarshal([]byte(byteVal), &Msites)
	if err != nil {
		log.Fatalf("Error while unmarshalling the read bytes into sites: %e", err)
	}

	worker_ctx, wrks_cancel := context.WithCancel(context.Background())

	reschan := make(chan Result, len(Msites.Sites))
	for i := range len(Msites.Sites) {
		log.Printf("Worker %d started", i)
		wg.Add(1)
		go startWorker(Msites.Sites[i], *interval, reschan, worker_ctx, &wg)
	}

	go startLogger(reschan)

	// Shutdown code & clean up code
	sig := <-killChan
	log.Println("Received signal:", sig)
	wrks_cancel()
	wg.Wait()
	close(reschan)

}
