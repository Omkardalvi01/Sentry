// Sentry DAST — Dynamic Application Security Testing tool.
// This is the CLI entry point.
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/Omkardalvi01/sentry/internal/config"
	"github.com/Omkardalvi01/sentry/internal/consumer"
	dashboardapi "github.com/Omkardalvi01/sentry/internal/dashboard"
	"github.com/Omkardalvi01/sentry/internal/graph"
	"github.com/Omkardalvi01/sentry/internal/model"
	"github.com/Omkardalvi01/sentry/internal/parser"
	"github.com/Omkardalvi01/sentry/internal/scanner"
	"github.com/Omkardalvi01/sentry/internal/storage"
)

var (
	version = "0.2.0"
	cfg     = config.Default()
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "sentry",
		Short: "Sentry — Dynamic Application Security Testing",
		Long: `Sentry is a DAST tool that ingests API specifications (OpenAPI 3.x / Swagger 2.0)
into a Memgraph graph database, building a rich, queryable attack-surface representation
for automated security testing.`,
		Version: version,
	}

	// Persistent flags (available to all subcommands)
	rootCmd.PersistentFlags().StringVar(&cfg.MemgraphURI, "memgraph-uri", cfg.MemgraphURI,
		"Memgraph Bolt URI (env: SENTRY_MEMGRAPH_URI)")
	rootCmd.PersistentFlags().StringVar(&cfg.MemgraphUser, "memgraph-user", cfg.MemgraphUser,
		"Memgraph username (env: SENTRY_MEMGRAPH_USER)")
	rootCmd.PersistentFlags().StringVar(&cfg.MemgraphPass, "memgraph-pass", cfg.MemgraphPass,
		"Memgraph password (env: SENTRY_MEMGRAPH_PASS)")
	rootCmd.PersistentFlags().BoolVarP(&cfg.Verbose, "verbose", "v", cfg.Verbose,
		"Enable verbose output")

	// Ingest subcommand
	rootCmd.AddCommand(ingestCmd())
	// Scan subcommand
	rootCmd.AddCommand(scanCmd())
	rootCmd.AddCommand(scanSpecCmd())
	rootCmd.AddCommand(replayCmd())
	// Consume traffic subcommand
	rootCmd.AddCommand(consumeTrafficCmd())
	rootCmd.AddCommand(dashboardCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func dashboardCmd() *cobra.Command {
	var dir, host, dbPath string
	var port int
	cmd := &cobra.Command{
		Use:   "dashboard",
		Short: "Serve the Sentry dashboard and HTTP API",
		RunE: func(cmd *cobra.Command, args []string) error {
			api, err := dashboardapi.New(dashboardapi.Config{DashboardDir: dir, DBPath: dbPath, MemgraphURI: cfg.MemgraphURI, MemgraphUser: cfg.MemgraphUser, MemgraphPass: cfg.MemgraphPass})
			if err != nil {
				return err
			}
			defer api.Close(context.Background())
			handler, err := api.Handler()
			if err != nil {
				return err
			}
			addr := fmt.Sprintf("%s:%d", host, port)
			fmt.Printf("✓ Dashboard listening at http://%s\n", addr)
			server := &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			go func() {
				<-ctx.Done()
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = server.Shutdown(shutdownCtx)
			}()
			err = server.ListenAndServe()
			if err == http.ErrServerClosed {
				return nil
			}
			return err
		},
	}
	cmd.Flags().StringVar(&dbPath, "sqlite-db", "traffic.db", "Shared traffic and scan database")
	cmd.Flags().StringVar(&dir, "dashboard-dir", "dashboard", "Directory containing dashboard HTML/CSS/JS")
	cmd.Flags().StringVar(&host, "host", "127.0.0.1", "HTTP listen host")
	cmd.Flags().IntVarP(&port, "port", "p", 8080, "HTTP listen port")
	return cmd
}

func ingestCmd() *cobra.Command {
	var (
		filePath string
		clean    bool
	)

	cmd := &cobra.Command{
		Use:   "ingest",
		Short: "Ingest an OpenAPI/Swagger spec into Memgraph",
		Long: `Parse an OpenAPI 3.x or Swagger 2.0 specification file and ingest it
into Memgraph as a graph of API paths, operations, and security schemes.

The graph uses a lean topological structure where paths and operations are nodes,
and schema details (parameters, request bodies, responses) are stored as JSON
properties on the operation nodes.`,
		Example: `  # Ingest a single spec
  sentry ingest --file openapi.yaml

  # Clean existing data before import
  sentry ingest --file openapi.yaml --clean

  # Specify custom Memgraph URI
  sentry ingest --file openapi.yaml --memgraph-uri bolt://db:7687`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runIngest(filePath, clean)
		},
	}

	cmd.Flags().StringVarP(&filePath, "file", "f", "", "Path to the OpenAPI/Swagger spec file (required)")
	cmd.Flags().BoolVar(&clean, "clean", false, "Wipe all existing graph data before import")
	_ = cmd.MarkFlagRequired("file")

	return cmd
}

func runIngest(filePath string, clean bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Validate file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return fmt.Errorf("spec file not found: %s", filePath)
	}

	// 1. Parse the spec
	fmt.Printf("⏳ Parsing spec: %s\n", filePath)
	p, err := parser.NewParser(filePath)
	if err != nil {
		return fmt.Errorf("creating parser: %w", err)
	}

	spec, err := p.Parse(filePath)
	if err != nil {
		return fmt.Errorf("parsing spec: %w", err)
	}
	fmt.Printf("✓ Parsed: %s v%s (%s %s)\n", spec.Title, spec.Version, spec.SpecFormat, spec.SpecVersion)

	// 2. Connect to Memgraph
	fmt.Printf("⏳ Connecting to Memgraph: %s\n", cfg.MemgraphURI)
	client, err := graph.NewClient(cfg.MemgraphURI, cfg.MemgraphUser, cfg.MemgraphPass)
	if err != nil {
		return fmt.Errorf("connecting to Memgraph: %w", err)
	}
	defer client.Close(ctx)

	if err := client.Ping(ctx); err != nil {
		return fmt.Errorf("pinging Memgraph: %w", err)
	}
	fmt.Println("✓ Connected to Memgraph")

	// 3. Ensure schema (indexes)
	if err := graph.EnsureSchema(ctx, client); err != nil {
		return fmt.Errorf("ensuring schema: %w", err)
	}

	// 4. Clean if requested
	if clean {
		fmt.Println("⚠ Wiping existing graph data...")
		if err := graph.WipeAll(ctx, client); err != nil {
			return fmt.Errorf("wiping graph: %w", err)
		}
		fmt.Println("✓ Graph wiped")
	}

	// 5. Ingest
	fmt.Println("⏳ Ingesting into Memgraph...")
	ingestor := graph.NewIngestor(client, cfg.Verbose)
	stats, err := ingestor.Ingest(ctx, spec)
	if err != nil {
		return fmt.Errorf("ingesting spec: %w", err)
	}

	// 6. Print summary
	fmt.Printf("\n✓ Ingested \"%s\" v%s (%s %s)\n", spec.Title, spec.Version, spec.SpecFormat, spec.SpecVersion)
	fmt.Println(stats.String())

	return nil
}

func scanCmd() *cobra.Command {
	scanCfg := &model.ScanConfig{}
	var headers []string
	var strategiesStr string

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan a live API target for zombie APIs and shadow endpoints",
		Long: `The scan command queries the Memgraph knowledge graph for the API attack surface,
and executes a series of detection strategies against a live target to find zombie APIs,
undocumented methods, and shadow endpoints.

Active scanning sends real HTTP requests. Only run against authorized targets.`,
		Example: `  # Scan with default settings
  sentry scan --target https://api.example.com

  # Scan with authentication headers and higher concurrency
  sentry scan --target https://api.example.com \
    --header "Authorization: Bearer token123" \
    --workers 10 --rps 20

  # Dry run to see what would be probed without sending requests
  sentry scan --target https://api.example.com --dry-run`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Parse headers
			scanCfg.Headers = scanner.ParseHeaders(headers)

			// Parse strategies
			if strategiesStr != "" {
				scanCfg.Strategies = strings.Split(strategiesStr, ",")
				for i := range scanCfg.Strategies {
					scanCfg.Strategies[i] = strings.TrimSpace(scanCfg.Strategies[i])
				}
			}

			scanCfg.Verbose = cfg.Verbose

			return runScan(scanCfg)
		},
	}

	cmd.Flags().StringVarP(&scanCfg.Target, "target", "t", "", "Base URL of the live API to scan (required)")
	cmd.Flags().StringVar(&scanCfg.SpecTitle, "spec-title", "", "Filter graph by spec title (optional)")
	cmd.Flags().StringVar(&scanCfg.SpecVer, "spec-version", "", "Filter graph by spec version (optional)")
	cmd.Flags().IntVarP(&scanCfg.Workers, "workers", "w", 5, "Number of concurrent workers")
	cmd.Flags().IntVarP(&scanCfg.RPS, "rps", "r", 10, "Maximum requests per second")
	cmd.Flags().DurationVar(&scanCfg.Timeout, "timeout", 15*time.Second, "Request timeout")
	cmd.Flags().StringSliceVarP(&headers, "header", "H", nil, "Custom header (e.g. 'Authorization: Bearer token')")
	cmd.Flags().StringVar(&strategiesStr, "strategies", "", "Comma-separated list of strategies to run (default: all)")
	cmd.Flags().IntVar(&scanCfg.MaxRequests, "max-requests", 0, "Total request budget including baselines (0 unlimited)")
	cmd.Flags().BoolVar(&scanCfg.AllowMutating, "allow-mutating", false, "Enable POST/PUT/PATCH/DELETE probes against resettable authorized targets")
	cmd.Flags().Int64Var(&scanCfg.MaxResponseBytes, "max-response-bytes", 1<<20, "Maximum response bytes used for validation")
	cmd.Flags().BoolVar(&scanCfg.DryRun, "dry-run", false, "Print probe plan without sending requests")
	cmd.Flags().BoolVarP(&scanCfg.Insecure, "insecure", "k", false, "Skip TLS verification")
	cmd.Flags().StringVarP(&scanCfg.Output, "output", "o", "table", "Output format (table or json)")

	_ = cmd.MarkFlagRequired("target")

	return cmd
}

func runScan(scanCfg *model.ScanConfig) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	fmt.Printf("⏳ Connecting to Memgraph: %s\n", cfg.MemgraphURI)
	client, err := graph.NewClient(cfg.MemgraphURI, cfg.MemgraphUser, cfg.MemgraphPass)
	if err != nil {
		return fmt.Errorf("connecting to Memgraph: %w", err)
	}
	defer client.Close(ctx)

	if err := client.Ping(ctx); err != nil {
		return fmt.Errorf("pinging Memgraph: %w", err)
	}
	fmt.Println("✓ Connected to Memgraph")

	engine := scanner.NewEngine(scanCfg, client)

	store, err := storage.NewTrafficStore("traffic.db")
	if err != nil {
		return err
	}
	defer store.Close()
	candidates, err := store.PassiveCandidates(ctx, scanCfg.SpecTitle, scanCfg.SpecVer)
	if err != nil {
		return err
	}
	scanCfg.PassiveCandidates = candidates
	scanCfg.RecordRequest = func(record *model.RequestRecord) error { return store.SaveRequest(context.Background(), record) }
	scanCfg.RecordProgress = func(scan *model.Scan) error { return store.SaveScan(context.Background(), scan, nil) }
	scan, findings, err := engine.Run(ctx)
	if scan != nil {
		if err != nil {
			scan.Status = "failed"
			scan.Error = err.Error()
			if ctx.Err() != nil {
				scan.Status = "cancelled"
			}
		}
		if persistErr := store.SaveScan(context.Background(), scan, findings); persistErr != nil {
			return persistErr
		}
	}
	if err != nil {
		return fmt.Errorf("running scan: %w", err)
	}

	if !scanCfg.DryRun {
		if scanCfg.Output == "json" {
			scanner.PrintJSONReport(scan, findings)
		} else {
			scanner.PrintTableReport(scan, findings)
		}
	}

	return nil
}

func consumeTrafficCmd() *cobra.Command {
	var (
		brokers string
		topic   string
		group   string
		dbPath  string
	)

	cmd := &cobra.Command{
		Use:   "consume-traffic",
		Short: "Consume API traffic events from Kafka and store them in SQLite",
		Long: `Connects to a Kafka broker, subscribes to an API gateway traffic topic,
and continuously writes JSON traffic events into a local SQLite database for offline analysis.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Setup graceful shutdown
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			brokerList := strings.Split(brokers, ",")
			fmt.Printf("⏳ Initializing SQLite database at %s...\n", dbPath)
			store, err := storage.NewTrafficStore(dbPath)
			if err != nil {
				return fmt.Errorf("initializing storage: %w", err)
			}
			defer store.Close()
			fmt.Println("✓ SQLite database initialized")

			fmt.Printf("⏳ Connecting to Memgraph: %s\n", cfg.MemgraphURI)
			graphClient, err := graph.NewClient(cfg.MemgraphURI, cfg.MemgraphUser, cfg.MemgraphPass)
			if err != nil {
				return fmt.Errorf("connecting to Memgraph: %w", err)
			}
			defer graphClient.Close(ctx)

			if err := graphClient.Ping(ctx); err != nil {
				return fmt.Errorf("pinging Memgraph: %w", err)
			}
			fmt.Println("✓ Connected to Memgraph")

			kafkaConsumer := consumer.NewKafkaConsumer(brokerList, topic, group, store, graphClient)
			defer kafkaConsumer.Close()

			fmt.Printf("⏳ Listening to Kafka topic '%s' on %s...\n", topic, brokers)
			if err := kafkaConsumer.Start(ctx); err != nil {
				return fmt.Errorf("consumer error: %w", err)
			}

			fmt.Println("\n✓ Shutdown complete.")
			return nil
		},
	}

	cmd.Flags().StringVarP(&brokers, "kafka-brokers", "k", "localhost:9092", "Comma-separated list of Kafka brokers")
	cmd.Flags().StringVarP(&topic, "kafka-topic", "t", "api-gateway-logs", "Kafka topic to consume")
	cmd.Flags().StringVarP(&group, "kafka-group", "g", "sentry-consumer", "Kafka consumer group ID")
	cmd.Flags().StringVarP(&dbPath, "sqlite-db", "d", "traffic.db", "Path to SQLite database file")

	return cmd
}
