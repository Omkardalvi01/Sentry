package scanner

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Omkardalvi01/sentry/internal/model"
)

// severityOrder maps severity levels to sort order.
var severityOrder = map[string]int{
	model.SeverityCritical: 0,
	model.SeverityHigh:     1,
	model.SeverityMedium:   2,
	model.SeverityLow:      3,
	model.SeverityInfo:     4,
}

// severityColors maps severity levels to ANSI color codes.
var severityColors = map[string]string{
	model.SeverityCritical: "\033[1;31m", // Bold Red
	model.SeverityHigh:     "\033[31m",   // Red
	model.SeverityMedium:   "\033[33m",   // Yellow
	model.SeverityLow:      "\033[36m",   // Cyan
	model.SeverityInfo:     "\033[37m",   // White
}

const colorReset = "\033[0m"

// PrintTableReport prints a human-readable table report of findings.
func PrintTableReport(scan *model.Scan, findings []*model.Finding) {
	// Sort findings by severity
	sorted := make([]*model.Finding, len(findings))
	copy(sorted, findings)
	sort.Slice(sorted, func(i, j int) bool {
		oi, oj := severityOrder[sorted[i].Severity], severityOrder[sorted[j].Severity]
		if oi != oj {
			return oi < oj
		}
		return sorted[i].Strategy < sorted[j].Strategy
	})

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                         SENTRY DAST — SCAN REPORT                          ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("  Target:     %s\n", scan.Target)
	fmt.Printf("  Scan ID:    %s\n", scan.ID)
	fmt.Printf("  Duration:   %s\n", scan.CompletedAt.Sub(scan.StartedAt).Round(time.Millisecond))
	fmt.Printf("  Probes:     %d sent\n", scan.ProbesSent)
	fmt.Printf("  Status:     %s\n", scan.Status)
	fmt.Println()

	if len(sorted) == 0 {
		fmt.Println("  ✅ No zombie APIs or vulnerabilities found.")
		fmt.Println()
		return
	}

	// Summary by severity
	counts := make(map[string]int)
	for _, f := range sorted {
		counts[f.Severity]++
	}

	fmt.Println("  ┌─ Summary ──────────────────────────────────────────────────────────────────")
	for _, sev := range []string{model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow, model.SeverityInfo} {
		if c, ok := counts[sev]; ok {
			color := severityColors[sev]
			fmt.Printf("  │  %s%-10s%s %d\n", color, sev, colorReset, c)
		}
	}
	fmt.Println("  │")
	fmt.Printf("  │  Total:     %d findings\n", len(sorted))
	fmt.Println("  └────────────────────────────────────────────────────────────────────────────")
	fmt.Println()

	// Detailed findings
	fmt.Println("  ┌─ Findings ─────────────────────────────────────────────────────────────────")
	for i, f := range sorted {
		color := severityColors[f.Severity]
		fmt.Printf("  │\n")
		fmt.Printf("  │  %s[%s]%s #%d — %s\n", color, f.Severity, colorReset, i+1, f.Title)
		fmt.Printf("  │  Strategy:    %s\n", f.Strategy)
		fmt.Printf("  │  Endpoint:    %s %s\n", f.Method, f.Path)
		fmt.Printf("  │  Status:      %d\n", f.StatusCode)
		fmt.Printf("  │  Target:      %s\n", f.Target)
		fmt.Printf("  │  Description: %s\n", wrapText(f.Description, 60, "  │               "))
		fmt.Printf("  │  Remediation: %s\n", wrapText(f.Remediation, 60, "  │               "))
	}
	fmt.Println("  │")
	fmt.Println("  └────────────────────────────────────────────────────────────────────────────")
	fmt.Println()
}

// PrintJSONReport prints a machine-readable JSON report.
func PrintJSONReport(scan *model.Scan, findings []*model.Finding) {
	report := map[string]interface{}{
		"scan":     scan,
		"findings": findings,
		"summary": map[string]interface{}{
			"total":    len(findings),
			"bySeverity": countBySeverity(findings),
			"byStrategy": countByStrategy(findings),
		},
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Printf("Error marshaling JSON: %v\n", err)
		return
	}
	fmt.Println(string(data))
}

func countBySeverity(findings []*model.Finding) map[string]int {
	counts := make(map[string]int)
	for _, f := range findings {
		counts[f.Severity]++
	}
	return counts
}

func countByStrategy(findings []*model.Finding) map[string]int {
	counts := make(map[string]int)
	for _, f := range findings {
		counts[f.Strategy]++
	}
	return counts
}

// wrapText wraps text at maxWidth, indenting continuation lines.
func wrapText(text string, maxWidth int, indent string) string {
	if len(text) <= maxWidth {
		return text
	}

	var lines []string
	words := strings.Fields(text)
	current := ""
	for _, word := range words {
		if len(current)+len(word)+1 > maxWidth {
			lines = append(lines, current)
			current = word
		} else {
			if current != "" {
				current += " "
			}
			current += word
		}
	}
	if current != "" {
		lines = append(lines, current)
	}

	if len(lines) == 0 {
		return text
	}
	return lines[0] + "\n" + indent + strings.Join(lines[1:], "\n"+indent)
}
