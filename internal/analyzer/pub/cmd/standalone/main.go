// Command standalone is a thin CLI runner for the in-process Dart/Pub analyzer.
// It runs the analyzer over a project root and prints findings as JSON. Used for
// development, the corpus gate, and real-repo empirical validation.
//
// Usage:
//
//	standalone -module /path/to/dart/project -adv-module some_package
//	standalone -module /path/to/dart/project -advisories advisories.json
//	standalone -module /path/to/dart/project -adv-module pkg -closure-incomplete
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	commit0v1 "github.com/commit0-dev/commit0-analyzer/pkg/contract/commit0v1"
	"github.com/commit0-dev/commit0-analyzer/internal/analyzer/pub"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "standalone: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		moduleRoot        = flag.String("module", "", "absolute path to the Dart project root (required)")
		advJSON           = flag.String("advisories", "", "path to a JSON file containing []Advisory")
		advID             = flag.String("adv-id", "", "single advisory ID (e.g. CVE-2024-0001)")
		advModule         = flag.String("adv-module", "", "single advisory package name (e.g. http)")
		closureIncomplete = flag.Bool("closure-incomplete", false, "simulate the host closure_incomplete signal")
	)
	flag.Parse()

	if *moduleRoot == "" {
		return fmt.Errorf("-module is required")
	}

	var advisories []*commit0v1.Advisory
	if *advJSON != "" {
		data, err := os.ReadFile(*advJSON)
		if err != nil {
			return fmt.Errorf("read advisories: %w", err)
		}
		if err := json.Unmarshal(data, &advisories); err != nil {
			return fmt.Errorf("parse advisories: %w", err)
		}
	} else if *advModule != "" {
		id := *advID
		if id == "" {
			id = "ADV-" + *advModule
		}
		advisories = append(advisories, &commit0v1.Advisory{Id: id, Module: *advModule})
	}

	a := &pub.Analyzer{
		Root:              *moduleRoot,
		Advisories:        advisories,
		ClosureIncomplete: *closureIncomplete,
	}

	type findingJSON struct {
		AdvisoryID string            `json:"advisory_id"`
		Module     string            `json:"module"`
		Confidence string            `json:"confidence"`
		Incomplete bool              `json:"incomplete,omitempty"`
		Properties map[string]string `json:"properties,omitempty"`
	}
	var out []findingJSON
	for _, f := range a.Analyze() {
		out = append(out, findingJSON{
			AdvisoryID: f.GetAdvisory().GetId(),
			Module:     f.GetModule(),
			Confidence: f.GetConfidence().String(),
			Incomplete: f.GetIncomplete(),
			Properties: f.GetProperties(),
		})
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
