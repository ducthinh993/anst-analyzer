//go:build parity

package parity

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestRunRequiresConfig exercises the runner's input validation without any
// network or external binaries.
func TestRunRequiresConfig(t *testing.T) {
	if _, err := Run(context.Background(), RunOptions{}); err == nil {
		t.Error("Run with no Commit0Binary should error")
	}
	if _, err := Run(context.Background(), RunOptions{Commit0Binary: "commit0-analyzer"}); err == nil {
		t.Error("Run with no ResolvePath should error")
	}
}

// TestParityHarness is the live harness. It scans the pinned corpus with a
// pre-built commit0-analyzer binary plus whatever comparator binaries are on PATH, measures
// the coverage gain of the full source set over the 2-source baseline, and writes
// the machine-readable report to reports/. It is opt-in: without
// COMMIT0_PARITY_COMMIT0_BIN it skips (it never fabricates numbers).
//
// Configuration (environment):
//
//	COMMIT0_PARITY_COMMIT0_BIN       path to a pre-built commit0-analyzer binary (required)
//	COMMIT0_PARITY_REPO_ROOT      local path for the self-scan entry (default: module root)
//	COMMIT0_PARITY_CHECKOUT_DIR   dir containing <corpus-name>/ checkouts pinned to Ref
//	                           (entries without a checkout are recorded as resolve
//	                           failures, never silently skipped)
//
// Run it with:
//
//	COMMIT0_PARITY_COMMIT0_BIN=/path/to/commit0-analyzer \
//	COMMIT0_PARITY_CHECKOUT_DIR=/path/to/checkouts \
//	go test -tags parity ./internal/advisory/parity/... -run TestParityHarness -v
func TestParityHarness(t *testing.T) {
	bin := os.Getenv("COMMIT0_PARITY_COMMIT0_BIN")
	if bin == "" {
		t.Skip("set COMMIT0_PARITY_COMMIT0_BIN to a pre-built commit0-analyzer binary to run the live parity harness")
	}
	repoRoot := os.Getenv("COMMIT0_PARITY_REPO_ROOT")
	if repoRoot == "" {
		// Default to the module root (three levels up from this package dir).
		repoRoot = filepath.Join("..", "..", "..")
	}
	checkoutDir := os.Getenv("COMMIT0_PARITY_CHECKOUT_DIR")

	opts := RunOptions{
		Commit0Binary: bin,
		Timeout:    10 * time.Minute,
		// Narrow the ecosystems we have validated reachability plugins for; others
		// auto-detect.
		Language: map[string]string{"go": "go", "python": "python"},
		ResolvePath: func(e CorpusEntry) (string, error) {
			if e.Name == "commit0-analyzer" {
				abs, err := filepath.Abs(repoRoot)
				if err != nil {
					return "", err
				}
				return abs, nil
			}
			if checkoutDir == "" {
				return "", fmt.Errorf("no checkout for %q (set COMMIT0_PARITY_CHECKOUT_DIR with a %s/ checkout pinned to %s)", e.Name, e.Name, e.Ref)
			}
			p := filepath.Join(checkoutDir, e.Name)
			if _, err := os.Stat(p); err != nil {
				return "", fmt.Errorf("checkout for %q not found at %s: %w", e.Name, p, err)
			}
			return p, nil
		},
	}

	rep, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if err := os.MkdirAll("reports", 0o755); err != nil {
		t.Fatalf("mkdir reports: %v", err)
	}
	jsonBytes, err := rep.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON: %v", err)
	}
	if err := os.WriteFile(filepath.Join("reports", "parity-report.json"), append(jsonBytes, '\n'), 0o644); err != nil {
		t.Fatalf("write json report: %v", err)
	}
	if err := os.WriteFile(filepath.Join("reports", "parity-report.md"), []byte(rep.ToMarkdown()), 0o644); err != nil {
		t.Fatalf("write md report: %v", err)
	}
	t.Logf("wrote reports/parity-report.{json,md}: %d comparisons, %d coverage-gain rows, %d assertions",
		len(rep.Comparisons), len(rep.CoverageGains), len(rep.Assertions))
}
