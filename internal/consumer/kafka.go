package consumer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/segmentio/kafka-go"
	"github.com/Omkardalvi01/sentry/internal/graph"
	"github.com/Omkardalvi01/sentry/internal/model"
	"github.com/Omkardalvi01/sentry/internal/storage"
)

// KafkaConsumer reads API traffic events from Kafka and stores them in SQLite.
type KafkaConsumer struct {
	reader      *kafka.Reader
	store       *storage.TrafficStore
	graphClient *graph.Client
	redisClient *redis.Client
	httpClient  *http.Client
	
	pathTemplates []string
	pathRegexes   []*regexp.Regexp
}

// NewKafkaConsumer initializes a new Kafka consumer.
func NewKafkaConsumer(brokers []string, topic, groupID string, store *storage.TrafficStore, gc *graph.Client) *KafkaConsumer {
	r := kafka.NewReader(kafka.ReaderConfig{
		Brokers:  brokers,
		Topic:    topic,
		GroupID:  groupID,
		MinBytes: 10e3, // 10KB
		MaxBytes: 10e6, // 10MB
	})

	redisURL := os.Getenv("SENTRY_REDIS_URL")
	if redisURL == "" {
		redisURL = "redis://localhost:6379"
	}
	opts, err := redis.ParseURL(redisURL)
	var rc *redis.Client
	if err == nil {
		rc = redis.NewClient(opts)
	}

	return &KafkaConsumer{
		reader:      r,
		store:       store,
		graphClient: gc,
		redisClient: rc,
		httpClient:  &http.Client{Timeout: 5 * time.Second},
	}
}

// initPaths pre-fetches and compiles path templates from the graph
func (c *KafkaConsumer) initPaths(ctx context.Context) {
	paths, err := c.graphClient.ReadPaths(ctx, "", "")
	if err != nil {
		log.Printf("⚠ Warning: Failed to pre-fetch path templates from graph: %v", err)
		return
	}
	c.pathTemplates = paths
	c.pathRegexes = make([]*regexp.Regexp, len(paths))
	
	// Convert OpenAPI path templates like /users/{id} to regex ^/users/[^/]+$
	paramRegex := regexp.MustCompile(`\{[^}]+\}`)
	for i, p := range paths {
		escaped := regexp.QuoteMeta(p)
		pattern := paramRegex.ReplaceAllString(escaped, `[^/]+`)
		c.pathRegexes[i] = regexp.MustCompile("^" + pattern + "$")
	}
}

func (c *KafkaConsumer) matchPathTemplate(rawPath string) string {
	for i, re := range c.pathRegexes {
		if re.MatchString(rawPath) {
			return c.pathTemplates[i]
		}
	}
	return rawPath // Fallback
}

func (c *KafkaConsumer) checkRedisCache(ctx context.Context, method, path string) bool {
	if c.redisClient == nil {
		return false
	}
	safePath := strings.ReplaceAll(path, ":", "_")
	key := fmt.Sprintf("sentry:ep:%s:%s", strings.ToUpper(method), safePath)
	val, err := c.redisClient.Get(ctx, key).Result()
	if err == redis.Nil || err != nil {
		return false
	}
	// Cache hit (meaning it's not an anomaly based on cache rules)
	return val != ""
}

// Start begins the consume loop. It blocks until the context is canceled.
func (c *KafkaConsumer) Start(ctx context.Context) error {
	log.Printf("Starting Kafka consumer for topic %s...", c.reader.Config().Topic)
	
	c.initPaths(ctx)

	const batchSize = 100
	var batch []model.TrafficEvent
	var lastMsg kafka.Message
	hasUncommitted := false

	pythonAPI := os.Getenv("SENTRY_PYTHON_API")
	if pythonAPI == "" {
		pythonAPI = "http://127.0.0.1:5001/predict"
	}

	for {
		fetchCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		m, err := c.reader.FetchMessage(fetchCtx)
		cancel()

		if err != nil {
			if fetchCtx.Err() == context.DeadlineExceeded {
				if len(batch) > 0 {
					if err := c.flushBatch(ctx, batch); err == nil && hasUncommitted {
						c.reader.CommitMessages(ctx, lastMsg)
						hasUncommitted = false
					}
					batch = batch[:0]
				}
				continue
			}
			if ctx.Err() != nil {
				c.flushBatch(context.Background(), batch)
				if hasUncommitted {
					c.reader.CommitMessages(context.Background(), lastMsg)
				}
				return nil
			}
			continue
		}

		var event model.TrafficEvent
		if err := json.Unmarshal(m.Value, &event); err != nil {
			c.reader.CommitMessages(ctx, m)
			continue
		}

		// 1. Check Redis Cache
		if !c.checkRedisCache(ctx, event.Method, event.Path) {
			// 2. Cache Miss: Resolve exact path template and fetch Graph Context
			matchedTemplate := c.matchPathTemplate(event.Path)
			event.GraphPathTemplate = matchedTemplate
			
			if gc, err := c.graphClient.ResolveTrafficContext(ctx, event.Method, matchedTemplate); err == nil {
				event.GraphDeprecated = gc.Deprecated
				event.GraphSecurity = gc.Security
				event.GraphTag = gc.Tag
				event.GraphDependencyCount = gc.DependencyCount
			}
			
			// 3. Call Python Anomaly Detector API
			payload, _ := json.Marshal(event)
			req, _ := http.NewRequestWithContext(ctx, "POST", pythonAPI, bytes.NewBuffer(payload))
			req.Header.Set("Content-Type", "application/json")
			if resp, err := c.httpClient.Do(req); err == nil {
				resp.Body.Close()
			} else {
				log.Printf("⚠ Failed to call python predict API: %v", err)
			}
		}

		batch = append(batch, event)
		lastMsg = m
		hasUncommitted = true

		if len(batch) >= batchSize {
			if err := c.flushBatch(ctx, batch); err == nil {
				c.reader.CommitMessages(ctx, lastMsg)
				hasUncommitted = false
			}
			batch = batch[:0]
		}
	}
}

func (c *KafkaConsumer) flushBatch(ctx context.Context, batch []model.TrafficEvent) error {
	if len(batch) == 0 {
		return nil
	}
	err := c.store.InsertBatch(ctx, batch)
	if err == nil {
		fmt.Printf("✓ Flushed %d API events to SQLite\n", len(batch))
	}
	return err
}

// Close shuts down the Kafka reader.
func (c *KafkaConsumer) Close() error {
	if c.redisClient != nil {
		c.redisClient.Close()
	}
	return c.reader.Close()
}
