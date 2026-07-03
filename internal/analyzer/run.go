package analyzer

import (
	"context"
	"fmt"
	"time"

	commit0v1 "github.com/commit0-dev/commit0-analyzer/pkg/contract/commit0v1"
)

// Result is the outcome of an in-process Analyze run.
type Result struct {
	// Findings is one finding per routed advisory (or one synthetic UNKNOWN per
	// routed advisory when the run failed).
	Findings []*commit0v1.Finding

	// Incomplete is true when the analyzer reported partial analysis, or when a
	// panic, timeout, or error degraded coverage to UNKNOWN.
	Incomplete bool

	// Err is non-nil on panic, timeout, or analyzer error. In every such case a
	// synthetic UNKNOWN finding is also appended per routed advisory, so the caller
	// never loses coverage — Err is only needed for logging.
	Err error
}

// Run executes a in-process with panic recovery and an optional timeout,
// mirroring the subprocess host's crash isolation (internal/host/run.go): a
// panic, a context timeout, or an analyzer error never propagates as a hard
// failure — instead every routed advisory degrades to one synthetic
// CONFIDENCE_UNKNOWN finding and the run is marked incomplete. This preserves the
// cardinal invariant unknown ≠ safe: an analyzer that dies mid-analysis widens
// its advisories to UNKNOWN (which count toward the policy gate), never silently
// drops them.
//
// A timeout <= 0 applies no per-analyzer deadline (only ctx governs). On timeout
// the analyzer goroutine may still be running; it is a bounded, read-only file
// walk that exits on its own, and Run returns the fail-closed result immediately —
// the same contract the subprocess host applies when it kills a timed-out process.
func Run(ctx context.Context, a Analyzer, in Input, timeout time.Duration) Result {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	type outcome struct {
		findings   []*commit0v1.Finding
		incomplete bool
		err        error
	}
	done := make(chan outcome, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- outcome{err: fmt.Errorf("analyzer %s: panic: %v", a.Name(), r)}
			}
		}()
		f, inc, err := a.Analyze(ctx, in)
		done <- outcome{findings: f, incomplete: inc, err: err}
	}()

	select {
	case o := <-done:
		if o.err != nil {
			return crashResult(a.Name(), in.Advisories, o.err)
		}
		return Result{Findings: o.findings, Incomplete: o.incomplete}
	case <-ctx.Done():
		return crashResult(a.Name(), in.Advisories,
			fmt.Errorf("analyzer %s: %w", a.Name(), ctx.Err()))
	}
}

// crashResult builds the fail-closed outcome for a panic, timeout, or error: one
// synthetic CONFIDENCE_UNKNOWN finding per routed advisory plus incomplete=true.
// A zero-advisory failure still reports incomplete so a crash is never a silent
// clean pass.
func crashResult(name string, advs []*commit0v1.Advisory, cause error) Result {
	r := Result{Incomplete: true, Err: cause}
	for _, adv := range advs {
		r.Findings = append(r.Findings, syntheticUnknown(name, adv, cause))
	}
	return r
}

// syntheticUnknown mirrors host/run.go's synthetic marker, attributed to a
// specific advisory: CONFIDENCE_UNKNOWN + Incomplete=true + Properties["synthetic"]
// so the host's partiality detection forces a non-zero exit. Unlike the
// subprocess host (which cannot see which advisories a killed plugin was working
// on and emits one marker), the in-process transport knows the routed set exactly
// and attributes one UNKNOWN to each advisory whose verdict was lost.
func syntheticUnknown(name string, adv *commit0v1.Advisory, cause error) *commit0v1.Finding {
	return &commit0v1.Finding{
		Advisory:   &commit0v1.AdvisoryRef{Id: adv.GetId()},
		Module:     adv.GetModule(),
		Confidence: commit0v1.Confidence_CONFIDENCE_UNKNOWN,
		Incomplete: true,
		Pillar:     "sca",
		Ecosystem:  adv.GetEcosystem(),
		Properties: map[string]string{
			"synthetic": "true",
			"cause":     cause.Error(),
			"analyzer":  name,
		},
	}
}
