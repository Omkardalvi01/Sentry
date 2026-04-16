package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"sync"
)

var methodFunc = map[string]func(site Site, ctx context.Context, res Result) Result{
	"GET": getFunc,
}

func startLogger(reschan chan Result, wg *sync.WaitGroup) {
	for result := range reschan {
		log.Printf("id : %s , url : %s , exp_status: %d , additional_info : %v\n", result.ID, result.Url, result.ExpectedStatus, result.Status)
	}
	wg.Done()
}

func getFunc(site Site, ctx context.Context, res Result) Result {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, site.Url, nil)
	if err != nil {
		res.Status = map[string]interface{}{"returned_status": http.StatusInternalServerError, "Same": false, "Error msg": err.Error()}
		return res
	}

	resp, err := http.DefaultClient.Do(req)
	if errors.Is(err, context.DeadlineExceeded) {
		res.Status = map[string]interface{}{"returned_status": http.StatusInternalServerError, "Same": false, "Error msg": "timed out "}
		return res
	}
	if err != nil {
		res.Status = map[string]interface{}{"returned_status": http.StatusInternalServerError, "Same": false, "Error msg": err.Error()}
		return res
	}
	defer resp.Body.Close()

	res.Status = map[string]interface{}{"returned_status": resp.StatusCode, "Same": resp.StatusCode == site.ExpectedStatus, "Additional": resp.StatusCode}

	return res
}
