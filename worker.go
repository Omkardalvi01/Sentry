package main

import (
	"context"
	"sync"
	"time"
)

type Result struct {
	ID             string
	Url            string
	ExpectedStatus int
	Status         map[string]interface{}
}

func startWorker(site Site, interval int, reschan chan Result, wrk_ctx context.Context, wg *sync.WaitGroup) {

	ticker := time.NewTicker(time.Duration(time.Second * time.Duration(interval)))
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			res := helper(site)
			reschan <- res
		case <-wrk_ctx.Done():
			wg.Done()
			return
		}
	}

}

func helper(site Site) Result {
	httpctx, cancel := context.WithTimeout(context.Background(), time.Duration(site.Timeout)*time.Millisecond)
	res := Result{ID: site.ID, Url: site.Url, ExpectedStatus: site.ExpectedStatus}
	defer cancel()

	res = methodFunc[site.Method](site, httpctx, res)
	return res
}
