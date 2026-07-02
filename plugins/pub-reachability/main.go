// Command pub-reachability is the commit0-analyzer plugin for Dart/Flutter
// (pub.dev) reachability-first SCA. It implements the commit0v1.Analyzer gRPC
// service via the shared pkg/plugin.Serve helper, mirroring rust-reachability.
//
// # Transport
//
// The host (internal/host) launches this binary as a subprocess and communicates
// over go-plugin's stdio-multiplexed gRPC transport. This binary must NOT write to
// stdout except through gRPC framing.
//
// # Reachability model
//
// The host resolves the pubspec.lock closure and passes it plus its
// closure_incomplete signal in the AnalyzeRequest; this plugin does NOT re-parse
// the lockfile. Its added value is NOT_REACHABLE: it builds the project's
// transitive used-import closure by lexing `import`/`export`/`part` directives —
// starting from project source and walking through each used package's own
// source (resolved via .dart_tool/package_config.json) — and emits:
//
//   - PACKAGE_REACHABLE when the advisory package is (transitively) imported,
//   - NOT_REACHABLE only from a complete, dynamism-frontier-clean closure, and
//   - UNKNOWN (Incomplete=true) for any incompleteness or frontier.
//
// # ACE safety
//
// Analysis is read-only static file reads under the project root and the resolved
// package source dirs. It NEVER runs `dart pub get` or any pub/dart subcommand
// (which would execute build hooks — arbitrary code execution) and makes no
// network calls (the namespace→package mapping is the identity function).
package main

import (
	"context"
	"fmt"

	commit0v1 "github.com/commit0-dev/commit0-analyzer/pkg/contract/commit0v1"
	commit0plugin "github.com/commit0-dev/commit0-analyzer/pkg/plugin"
	"github.com/commit0-dev/commit0-analyzer/plugins/pub-reachability/internal/engine"
)

// grpcServer implements commit0v1.AnalyzerServer for the Dart/Pub plugin.
type grpcServer struct {
	commit0v1.UnimplementedAnalyzerServer
}

// Metadata returns plugin identity and protocol version for the host handshake.
// It advertises protocol minor 2 (the additive resolved_deps / closure_incomplete
// fields this plugin consumes).
func (s *grpcServer) Metadata(
	_ context.Context,
	_ *commit0v1.MetadataRequest,
) (*commit0v1.MetadataResponse, error) {
	return &commit0v1.MetadataResponse{
		Name:               "pub-reachability",
		Version:            "0.1.0",
		ProtocolVersion:    "0.2",
		Description:        "Dart/Pub SCA reachability analyzer: used-import closure NOT_REACHABLE proof over the host-resolved pubspec.lock closure.",
		SupportedLanguages: []string{"dart"},
	}, nil
}

// Analyze runs the used-import reachability engine over the project root and
// streams one Finding per advisory to the host.
func (s *grpcServer) Analyze(
	req *commit0v1.AnalyzeRequest,
	stream commit0v1.Analyzer_AnalyzeServer,
) error {
	a := &engine.Analyzer{
		Root:              req.GetModuleRoot(),
		Advisories:        req.GetAdvisories(),
		ClosureIncomplete: req.GetClosureIncomplete(),
	}
	for _, f := range a.Analyze() {
		if err := stream.Send(f); err != nil {
			return fmt.Errorf("pub-reachability: stream.Send: %w", err)
		}
	}
	return nil
}

func main() {
	commit0plugin.Serve(&grpcServer{})
}
