package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"github.com/Omkardalvi01/sentry/internal/model"
	"github.com/segmentio/kafka-go"
	"github.com/spf13/cobra"
	"os"
	"time"
)

func replayCmd() *cobra.Command {
	var file, broker, topic string
	cmd := &cobra.Command{Use: "replay-traffic", Short: "Replay recorded research traffic JSONL into Kafka", RunE: func(cmd *cobra.Command, args []string) error {
		input, err := os.Open(file)
		if err != nil {
			return err
		}
		defer input.Close()
		writer := &kafka.Writer{Addr: kafka.TCP(broker), Topic: topic, AllowAutoTopicCreation: true, BatchTimeout: 10 * time.Millisecond}
		defer writer.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		scanner := bufio.NewScanner(input)
		scanner.Buffer(make([]byte, 65536), 10<<20)
		var messages []kafka.Message
		for scanner.Scan() {
			var e model.TrafficEvent
			if err = json.Unmarshal(scanner.Bytes(), &e); err != nil {
				return err
			}
			if e.RequestID == "" {
				return fmt.Errorf("missing request_id")
			}
			b, err := json.Marshal(e)
			if err != nil {
				return err
			}
			messages = append(messages, kafka.Message{Key: []byte(e.RequestID), Value: b})
		}
		if err = scanner.Err(); err != nil {
			return err
		}
		return writer.WriteMessages(ctx, messages...)
	}}
	cmd.Flags().StringVar(&file, "file", "", "Traffic JSONL file")
	cmd.Flags().StringVar(&broker, "broker", "127.0.0.1:19092", "Kafka broker")
	cmd.Flags().StringVar(&topic, "topic", "api-gateway-logs", "Kafka topic")
	_ = cmd.MarkFlagRequired("file")
	return cmd
}
