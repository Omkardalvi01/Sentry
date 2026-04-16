package main

import (
	"context"
	"sync"
	"time"
)

type Result struct {
	ID            string
	Status        string
	Status_Code   int
	Method        string
	Response_time int
	Checked_at    time.Time
	Error         string
	Data          map[string]interface{}
}

func startWorker(site Site, interval int, reschan chan Result, wrk_ctx context.Context, wg *sync.WaitGroup) {

	ticker := time.NewTicker(time.Duration(time.Second * time.Duration(interval)))
	defer ticker.Stop()
	for {
		select {
		case <-wrk_ctx.Done():
			wg.Done()
			return
		case <-ticker.C:
			res := dispatcher(site)
			reschan <- res
		}
	}

}

func dispatcher(site Site) Result {
	httpctx, cancel := context.WithTimeout(context.Background(), time.Duration(site.Timeout)*time.Millisecond)
	defer cancel()

	res := methodFunc[site.Method](site, httpctx)
	return res
}
