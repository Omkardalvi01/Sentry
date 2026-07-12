package consumer

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/segmentio/kafka-go"
	"github.com/Omkardalvi01/sentry/internal/model"
	"github.com/Omkardalvi01/sentry/internal/storage"
)

// KafkaConsumer reads API traffic events from Kafka and stores them in SQLite.
type KafkaConsumer struct {
	reader *kafka.Reader
	store  *storage.TrafficStore
}

// NewKafkaConsumer initializes a new Kafka consumer.
func NewKafkaConsumer(brokers []string, topic, groupID string, store *storage.TrafficStore) *KafkaConsumer {
	r := kafka.NewReader(kafka.ReaderConfig{
		Brokers:  brokers,
		Topic:    topic,
		GroupID:  groupID,
		MinBytes: 10e3, // 10KB
		MaxBytes: 10e6, // 10MB
	})

	return &KafkaConsumer{
		reader: r,
		store:  store,
	}
}

// Start begins the consume loop. It blocks until the context is canceled.
func (c *KafkaConsumer) Start(ctx context.Context) error {
	log.Printf("Starting Kafka consumer for topic %s...", c.reader.Config().Topic)

	const batchSize = 100
	var batch []model.TrafficEvent
	var lastMsg kafka.Message
	hasUncommitted := false

	for {
		// Use a short timeout so we can flush partial batches if traffic is low.
		fetchCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		m, err := c.reader.FetchMessage(fetchCtx)
		cancel()

		if err != nil {
			// If it's just a timeout and we have a partial batch, flush it.
			if fetchCtx.Err() == context.DeadlineExceeded {
				if len(batch) > 0 {
					if err := c.flushBatch(ctx, batch); err != nil {
						log.Printf("⚠ Error flushing batch on timeout: %v", err)
					} else if hasUncommitted {
						if err := c.reader.CommitMessages(ctx, lastMsg); err != nil {
							log.Printf("⚠ Error committing offsets: %v", err)
						}
						hasUncommitted = false
					}
					batch = batch[:0]
				}
				continue
			}

			// If the main context was canceled, flush and exit
			if ctx.Err() != nil {
				c.flushBatch(context.Background(), batch)
				if hasUncommitted {
					c.reader.CommitMessages(context.Background(), lastMsg)
				}
				return nil
			}

			log.Printf("⚠ Error fetching message: %v", err)
			continue
		}

		var event model.TrafficEvent
		if err := json.Unmarshal(m.Value, &event); err != nil {
			log.Printf("⚠ Error unmarshalling event, skipping: %v", err)
			c.reader.CommitMessages(ctx, m) // skip and commit
			continue
		}

		batch = append(batch, event)
		lastMsg = m
		hasUncommitted = true

		// If batch is full, flush it
		if len(batch) >= batchSize {
			if err := c.flushBatch(ctx, batch); err != nil {
				log.Printf("⚠ Error flushing full batch: %v", err)
			} else {
				if err := c.reader.CommitMessages(ctx, lastMsg); err != nil {
					log.Printf("⚠ Error committing offsets: %v", err)
				}
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
	return c.reader.Close()
}
