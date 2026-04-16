package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"
)

var methodFunc = map[string]func(site Site, ctx context.Context) Result{
	"GET": getFunc,
}

func getFunc(site Site, ctx context.Context) Result {
	res := Result{ID: site.ID, Method: site.Method, Checked_at: time.Now()}

	setStatus := func(success bool, status string, status_code int, errStr string) {
		if !success {
			res.Error = errStr
		}
		res.Status = status
		res.Status_Code = status_code
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, site.Url, nil)
	if err != nil {
		setStatus(false, "DOWN", http.StatusInternalServerError, err.Error())
		return res
	}

	resp, err := http.DefaultClient.Do(req)
	if errors.Is(err, context.DeadlineExceeded) {
		setStatus(false, "DOWN", http.StatusInternalServerError, "Request was timed out")
		return res
	}
	if err != nil {
		setStatus(false, "DOWN", http.StatusInternalServerError, err.Error())
		return res
	}
	defer resp.Body.Close()

	setStatus(true, "UP", http.StatusOK, "")

	return res
}

func startLogger(reschan chan Result) {
	for result := range reschan {
		if result.Status == "DOWN" {
			log.Printf("id: %s , method: %s status:%s status_code:%d, checked_at:%v error:%s\n", result.ID, result.Method, result.Status, result.Status_Code, result.Checked_at.Format("2006-01-02 3:4:5 pm"), result.Error)
			continue
		}
		log.Printf("id: %s method: %s status:%s status_code:%d, checked_at:%v\n", result.ID, result.Method, result.Status, result.Status_Code, result.Checked_at.Format("2006-01-02 3:4:5 pm"))
	}

}
