package model

import "time"

// Severity levels for findings.
const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityInfo     = "INFO"
)

// Strategy names for zombie API detection.
const (
	StrategyDeprecatedAlive = "deprecated_alive"
	StrategyVersionProbe    = "version_probe"
	StrategyMethodProbe     = "method_probe"
	StrategyShadowPath      = "shadow_path"
	StrategyAuthBypass      = "auth_bypass"
)

// AllStrategies lists all available strategy names.
var AllStrategies = []string{
	StrategyDeprecatedAlive,
	StrategyVersionProbe,
	StrategyMethodProbe,
	StrategyShadowPath,
	StrategyAuthBypass,
}

// Finding represents a security finding from the scanner.
type Finding struct {
	ID          string    `json:"id"`
	Strategy    string    `json:"strategy"`
	Severity    string    `json:"severity"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Path        string    `json:"path"`
	Method      string    `json:"method"`
	Target      string    `json:"target"`
	StatusCode  int       `json:"statusCode"`
	Evidence    string    `json:"evidence"`
	Remediation string    `json:"remediation"`
	Timestamp   time.Time `json:"timestamp"`
}

// Scan represents metadata about a scan run.
type Scan struct {
	ID            string    `json:"id"`
	Target        string    `json:"target"`
	SpecTitle     string    `json:"specTitle"`
	SpecVersion   string    `json:"specVersion"`
	Strategies    []string  `json:"strategies"`
	StartedAt     time.Time `json:"startedAt"`
	CompletedAt   time.Time `json:"completedAt"`
	FindingsCount int       `json:"findingsCount"`
	ProbesSent    int       `json:"probesSent"`
	Status        string    `json:"status"` // "running", "completed", "failed"
}

// Probe defines a single HTTP request to be sent during scanning.
type Probe struct {
	URL      string            // Full URL to probe
	Path     string            // Path component only
	Method   string            // HTTP method
	Headers  map[string]string // Custom headers
	Body     string            // Request body (if any)
	Strategy string            // Which strategy generated this probe
	Meta     map[string]string // Extra metadata (e.g. original operationId)
}

// ProbeResult captures the outcome of sending a probe.
type ProbeResult struct {
	Probe      *Probe
	StatusCode int
	Headers    map[string][]string
	Body       string        // First 512 bytes of response body
	Duration   time.Duration // Round-trip time
	Error      error         // Non-nil if request failed
}

// ScanConfig holds scanner configuration.
type ScanConfig struct {
	Target     string            // Base URL to scan
	SpecTitle  string            // Spec to use from graph
	SpecVer    string            // Spec version to use
	Workers    int               // Concurrent workers
	RPS        int               // Requests per second limit
	Timeout    time.Duration     // Per-request timeout
	Headers    map[string]string // Custom headers (e.g. auth)
	Strategies []string          // Which strategies to run
	DryRun     bool              // Print probe plan without sending
	Insecure   bool              // Skip TLS verification
	Output     string            // "table" or "json"
	Verbose    bool
}


