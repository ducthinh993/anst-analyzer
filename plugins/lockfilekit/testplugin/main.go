// Command commit0-lockfilekit-reachability is a working reference plugin used by
// the host's plugin-dispatch integration test. It is intentionally minimal but
// NOT a stub: it implements the full Analyzer handshake and streams a real
// Finding per advisory, echoing what the host handed it via the additive
// resolved_deps / closure_incomplete fields so the test can prove the closure
// actually reached the plugin.
//
// It advertises protocol version "0.2" (the minor bump that added resolved_deps),
// demonstrating that a plugin declaring minor 2 loads against a host at minor 2.
//
// The verdict it emits is NOT_REACHABLE for every advisory — the tier a real
// lockfile plugin exists to add. This lets the dispatch test assert both that the
// direct host finding was suppressed and that the plugin's NOT_REACHABLE surfaced.
package main

import (
	"context"
	"fmt"
	"strconv"

	commit0v1 "github.com/commit0-dev/commit0-analyzer/pkg/contract/commit0v1"
	commit0plugin "github.com/commit0-dev/commit0-analyzer/pkg/plugin"
)

type grpcServer struct {
	commit0v1.UnimplementedAnalyzerServer
}

func (s *grpcServer) Metadata(
	_ context.Context,
	_ *commit0v1.MetadataRequest,
) (*commit0v1.MetadataResponse, error) {
	return &commit0v1.MetadataResponse{
		Name:               "lockfilekit-reachability",
		Version:            "0.0.1",
		ProtocolVersion:    "0.2",
		Description:        "lockfilekit dispatch test plugin: echoes resolved_deps and emits NOT_REACHABLE.",
		SupportedLanguages: []string{"java"},
	}, nil
}

// Analyze emits one NOT_REACHABLE finding per advisory, stamping the count of
// resolved_deps it received and the closure_incomplete flag so the host-side
// test can verify the closure was delivered over the wire.
func (s *grpcServer) Analyze(
	req *commit0v1.AnalyzeRequest,
	stream commit0v1.Analyzer_AnalyzeServer,
) error {
	depCount := strconv.Itoa(len(req.GetResolvedDeps()))
	closureIncomplete := strconv.FormatBool(req.GetClosureIncomplete())

	for _, adv := range req.GetAdvisories() {
		f := &commit0v1.Finding{
			Advisory:   &commit0v1.AdvisoryRef{Id: adv.GetId()},
			Module:     adv.GetModule(),
			Confidence: commit0v1.Confidence_CONFIDENCE_NOT_REACHABLE,
			Pillar:     "sca",
			Language:   "java",
			Ecosystem:  adv.GetEcosystem(),
			Properties: map[string]string{
				"echo":                "true",
				"resolved_deps_count": depCount,
				"closure_incomplete":  closureIncomplete,
				"reason":              "lockfilekit test plugin: advisory package not referenced in project source",
			},
		}
		if err := stream.Send(f); err != nil {
			return fmt.Errorf("lockfilekit-reachability: stream.Send: %w", err)
		}
	}
	return nil
}

func main() {
	commit0plugin.Serve(&grpcServer{})
}
