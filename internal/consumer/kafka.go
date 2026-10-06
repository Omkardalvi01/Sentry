package consumer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Omkardalvi01/sentry/internal/graph"
	"github.com/Omkardalvi01/sentry/internal/model"
	"github.com/Omkardalvi01/sentry/internal/storage"
	"github.com/redis/go-redis/v9"
	"github.com/segmentio/kafka-go"
)

type KafkaConsumer struct {
	redisClient *redis.Client
	reader      *kafka.Reader
	store       *storage.TrafficStore
	graphClient *graph.Client
	httpClient  *http.Client
	ops         []graph.OperationWithPath
	refreshed   time.Time
	pythonAPI   string
}

func NewKafkaConsumer(brokers []string, topic, group string, store *storage.TrafficStore, g *graph.Client) *KafkaConsumer {
	api := os.Getenv("SENTRY_PYTHON_API")
	if api == "" {
		api = "http://127.0.0.1:5001/predict"
	}
	var cache *redis.Client
	if raw := os.Getenv("SENTRY_REDIS_URL"); raw != "" {
		if opts, err := redis.ParseURL(raw); err == nil {
			opts.ReadTimeout = time.Second
			opts.WriteTimeout = time.Second
			opts.MaxRetries = 0
			cache = redis.NewClient(opts)
		}
	}
	return &KafkaConsumer{redisClient: cache, reader: kafka.NewReader(kafka.ReaderConfig{Brokers: brokers, Topic: topic, GroupID: group, MinBytes: 1, MaxBytes: 10e6}), store: store, graphClient: g, httpClient: &http.Client{Timeout: 5 * time.Second}, pythonAPI: api}
}
func (c *KafkaConsumer) refresh(ctx context.Context) error {
	if time.Since(c.refreshed) < time.Minute {
		return nil
	}
	if c.redisClient != nil {
		cacheCtx, cancel := context.WithTimeout(ctx, time.Second)
		raw, err := c.redisClient.Get(cacheCtx, c.graphClient.InventoryCacheKey()).Bytes()
		cancel()
		if err == nil && json.Unmarshal(raw, &c.ops) == nil {
			c.refreshed = time.Now()
			return nil
		}
	}
	ops, err := c.graphClient.ReadOperationsWithPaths(ctx, "", "")
	if err != nil {
		return err
	}
	if c.redisClient != nil {
		raw, _ := json.Marshal(ops)
		cacheCtx, cancel := context.WithTimeout(ctx, time.Second)
		_ = c.redisClient.Set(cacheCtx, c.graphClient.InventoryCacheKey(), raw, time.Minute).Err()
		cancel()
	}
	c.ops = ops
	c.refreshed = time.Now()
	return nil
}
func (c *KafkaConsumer) enrich(ctx context.Context, e *model.TrafficEvent) {
	e.GraphKnown = nil
	e.GraphContextStatus = "unknown"
	e.GraphDependencyCount = 0
	if err := c.refresh(ctx); err != nil {
		e.GraphContextStatus = "unavailable"
		return
	}
	// Select a single spec. Never conflate operations belonging to different APIs.
	scopes := map[string]bool{}
	templates := []string{}
	for _, op := range c.ops {
		if (e.SpecTitle == "" || e.SpecTitle == op.SpecTitle) && (e.SpecVersion == "" || e.SpecVersion == op.SpecVersion) {
			scopes[model.OperationKey(op.SpecTitle, op.SpecVersion, "", "")] = true
			templates = append(templates, op.PathTemplate)
		}
	}
	if len(scopes) != 1 {
		e.GraphContextStatus = "ambiguous"
		return
	}
	template := model.MatchTemplate(e.Path, templates)
	e.GraphPathTemplate = template
	known := false
	e.GraphKnown = &known
	e.GraphContextStatus = "resolved"
	for _, op := range c.ops {
		if (e.SpecTitle == "" || e.SpecTitle == op.SpecTitle) && (e.SpecVersion == "" || e.SpecVersion == op.SpecVersion) {
			e.SpecTitle, e.SpecVersion = op.SpecTitle, op.SpecVersion
			if op.PathTemplate == template && op.Method == e.Method {
				known = true
				e.GraphDeprecated = op.Deprecated
				e.GraphSecurity = op.Security
				if len(op.Tags) > 0 {
					e.GraphTag = op.Tags[0]
				}
				break
			}
		}
	}
}
func (c *KafkaConsumer) evaluate(ctx context.Context, e model.TrafficEvent) (string, json.RawMessage) {
	payload, err := json.Marshal(e)
	if err != nil {
		return "pending", json.RawMessage(`{"error":"invalid event"}`)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.pythonAPI, bytes.NewReader(payload))
	if err != nil {
		return "pending", json.RawMessage(`{"error":"invalid prediction URL"}`)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "pending", json.RawMessage(`{"error":"detector unavailable"}`)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var result map[string]any
	if err != nil || resp.StatusCode != 200 || json.Unmarshal(b, &result) != nil {
		return "pending", json.RawMessage(`{"error":"detector response failed"}`)
	}
	if result["evaluation_status"] != "evaluated" {
		return "pending", b
	}
	return "evaluated", b
}
func validateEvent(e model.TrafficEvent) error {
	if e.RequestID == "" || !strings.HasPrefix(e.Path, "/") || e.Timestamp.IsZero() || e.StatusCode < 100 || e.StatusCode > 599 {
		return fmt.Errorf("request_id, absolute path, timestamp, and valid status_code are required")
	}
	switch e.Method {
	case "GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE", "TRACE":
		return nil
	}
	return fmt.Errorf("invalid HTTP method")
}
func (c *KafkaConsumer) retryPending(ctx context.Context) {
	events, err := c.store.Pending(ctx)
	if err != nil {
		log.Printf("pending reads: %v", err)
		return
	}
	for i, e := range events {
		if i >= 5 {
			break
		}
		if ctx.Err() != nil {
			return
		}
		c.enrich(ctx, &e)
		status, b := c.evaluate(ctx, e)
		if status == "evaluated" {
			if err := c.store.SavePrediction(ctx, e, status, b); err != nil {
				log.Printf("pending persistence: %v", err)
			}
		}
	}
}
func (c *KafkaConsumer) Start(ctx context.Context) error {
	log.Printf("Consuming %s; offsets commit after durable traffic/prediction handling", c.reader.Config().Topic)
	retryAt := time.Time{}
	for {
		if ctx.Err() != nil {
			return nil
		}
		if time.Since(retryAt) > 10*time.Second {
			c.retryPending(ctx)
			retryAt = time.Now()
		}
		fetchCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		m, err := c.reader.FetchMessage(fetchCtx)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if err == context.DeadlineExceeded {
				continue
			}
			log.Printf("Kafka fetch: %v", err)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(time.Second):
			}
			continue
		}
		var event model.TrafficEvent
		decodeErr := json.Unmarshal(m.Value, &event)
		event.Method = strings.ToUpper(event.Method)
		if decodeErr == nil {
			decodeErr = validateEvent(event)
		}
		if decodeErr != nil {
			if err := c.store.Reject(ctx, fmt.Sprintf("%s:%d:%d", m.Topic, m.Partition, m.Offset), decodeErr.Error()); err != nil {
				return err
			}
		} else {
			exists, err := c.store.HasEvent(ctx, event.RequestID)
			if err != nil {
				return err
			}
			if !exists {
				c.enrich(ctx, &event)
				status, b := c.evaluate(ctx, event)
				if err := c.store.SavePrediction(ctx, event, status, b); err != nil {
					return fmt.Errorf("durable write failed; Kafka offset left uncommitted: %w", err)
				}
			}
		}
		if err := c.reader.CommitMessages(ctx, m); err != nil {
			return fmt.Errorf("commit failed; durable event can be replayed: %w", err)
		}
	}
}
func (c *KafkaConsumer) Close() error {
	if c.redisClient != nil {
		c.redisClient.Close()
	}
	return c.reader.Close()
}
