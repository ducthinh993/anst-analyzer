package analyzer

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commit0v1 "github.com/commit0-dev/commit0-analyzer/pkg/contract/commit0v1"
)

// fakeAnalyzer is a test double whose Analyze behavior is injected per case.
type fakeAnalyzer struct {
	name string
	ecos []string
	fn   func(ctx context.Context, in Input) ([]*commit0v1.Finding, bool, error)
}

func (f fakeAnalyzer) Name() string               { return f.name }
func (f fakeAnalyzer) Ecosystems() []string        { return f.ecos }
func (f fakeAnalyzer) Analyze(ctx context.Context, in Input) ([]*commit0v1.Finding, bool, error) {
	return f.fn(ctx, in)
}

func testAdvisories(ids ...string) []*commit0v1.Advisory {
	out := make([]*commit0v1.Advisory, len(ids))
	for i, id := range ids {
		out[i] = &commit0v1.Advisory{Id: id, Module: id + "-pkg", Ecosystem: commit0v1.Ecosystem_ECOSYSTEM_NPM}
	}
	return out
}

// TestRun_Success passes findings and the incomplete flag through unchanged and
// sets no error.
func TestRun_Success(t *testing.T) {
	want := []*commit0v1.Finding{{Module: "a", Confidence: commit0v1.Confidence_CONFIDENCE_NOT_REACHABLE}}
	a := fakeAnalyzer{name: "x", fn: func(_ context.Context, _ Input) ([]*commit0v1.Finding, bool, error) {
		return want, false, nil
	}}
	res := Run(context.Background(), a, Input{Advisories: testAdvisories("CVE-1")}, 0)
	require.NoError(t, res.Err)
	assert.False(t, res.Incomplete)
	assert.Equal(t, want, res.Findings)
}

// TestRun_IncompletePropagates carries the analyzer's incomplete flag out.
func TestRun_IncompletePropagates(t *testing.T) {
	a := fakeAnalyzer{name: "x", fn: func(_ context.Context, _ Input) ([]*commit0v1.Finding, bool, error) {
		return nil, true, nil
	}}
	res := Run(context.Background(), a, Input{Advisories: testAdvisories("CVE-1")}, 0)
	require.NoError(t, res.Err)
	assert.True(t, res.Incomplete)
}

// assertSyntheticPerAdvisory is the shared fail-closed assertion: the crash
// semantics emit exactly one synthetic CONFIDENCE_UNKNOWN finding per routed
// advisory, each carrying the partiality markers the host reads to force exit 3.
func assertSyntheticPerAdvisory(t *testing.T, res Result, advs []*commit0v1.Advisory) {
	t.Helper()
	require.Error(t, res.Err, "a panic/timeout/error must surface an error")
	assert.True(t, res.Incomplete, "a failed run must mark the scan incomplete (unknown ≠ safe)")
	require.Len(t, res.Findings, len(advs), "one synthetic UNKNOWN per routed advisory (no coverage dropped)")

	byModule := make(map[string]*commit0v1.Finding, len(res.Findings))
	for _, f := range res.Findings {
		assert.Equal(t, commit0v1.Confidence_CONFIDENCE_UNKNOWN, f.GetConfidence(),
			"a lost verdict degrades to UNKNOWN, never NOT_REACHABLE")
		assert.True(t, f.GetIncomplete(), "synthetic UNKNOWN must carry Incomplete=true")
		assert.Equal(t, "true", f.GetProperties()["synthetic"], "synthetic UNKNOWN must carry the synthetic marker")
		assert.NotEmpty(t, f.GetProperties()["cause"], "synthetic UNKNOWN must record the cause")
		byModule[f.GetModule()] = f
	}
	for _, adv := range advs {
		f, ok := byModule[adv.GetModule()]
		require.True(t, ok, "every advisory %q must yield a synthetic finding", adv.GetId())
		assert.Equal(t, adv.GetId(), f.GetAdvisory().GetId(), "synthetic finding must be attributed to its advisory")
	}
}

// TestRun_PanicYieldsSyntheticUnknownPerAdvisory proves an analyzer panic is
// isolated: the scan completes and every routed advisory degrades to a synthetic
// UNKNOWN, mirroring the subprocess host's crash isolation.
func TestRun_PanicYieldsSyntheticUnknownPerAdvisory(t *testing.T) {
	advs := testAdvisories("CVE-1", "CVE-2", "CVE-3")
	a := fakeAnalyzer{name: "boom", fn: func(_ context.Context, _ Input) ([]*commit0v1.Finding, bool, error) {
		panic("engine exploded")
	}}
	res := Run(context.Background(), a, Input{Advisories: advs}, 0)
	assertSyntheticPerAdvisory(t, res, advs)
	assert.Contains(t, res.Err.Error(), "panic")
}

// TestRun_TimeoutYieldsSyntheticUnknownPerAdvisory proves a per-analyzer timeout
// degrades to the same fail-closed result as a panic.
func TestRun_TimeoutYieldsSyntheticUnknownPerAdvisory(t *testing.T) {
	advs := testAdvisories("CVE-1", "CVE-2")
	a := fakeAnalyzer{name: "slow", fn: func(ctx context.Context, _ Input) ([]*commit0v1.Finding, bool, error) {
		<-ctx.Done() // block until the transport's timeout cancels us
		return nil, false, ctx.Err()
	}}
	res := Run(context.Background(), a, Input{Advisories: advs}, 10*time.Millisecond)
	assertSyntheticPerAdvisory(t, res, advs)
}

// TestRun_AnalyzerErrorYieldsSynthetic proves a returned error (operational
// failure) is treated as a crash, not a clean empty result.
func TestRun_AnalyzerErrorYieldsSynthetic(t *testing.T) {
	advs := testAdvisories("CVE-1")
	a := fakeAnalyzer{name: "err", fn: func(_ context.Context, _ Input) ([]*commit0v1.Finding, bool, error) {
		return nil, false, errors.New("resolve failed")
	}}
	res := Run(context.Background(), a, Input{Advisories: advs}, 0)
	assertSyntheticPerAdvisory(t, res, advs)
}

// TestRun_PanicWithNoAdvisoriesStillIncomplete proves a crash is never a silent
// clean pass even when no advisory was routed: incomplete stays true.
func TestRun_PanicWithNoAdvisoriesStillIncomplete(t *testing.T) {
	a := fakeAnalyzer{name: "boom", fn: func(_ context.Context, _ Input) ([]*commit0v1.Finding, bool, error) {
		panic("boom")
	}}
	res := Run(context.Background(), a, Input{}, 0)
	require.Error(t, res.Err)
	assert.True(t, res.Incomplete)
	assert.Empty(t, res.Findings)
}
