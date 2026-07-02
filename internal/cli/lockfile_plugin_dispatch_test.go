package cli

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/commit0-dev/commit0-analyzer/internal/advisory"
	"github.com/commit0-dev/commit0-analyzer/internal/host"
	commit0v1 "github.com/commit0-dev/commit0-analyzer/pkg/contract/commit0v1"
)

// buildLockfileTestPlugin compiles the lockfilekit reference/test plugin, which
// echoes the resolved_deps + closure_incomplete it received and emits
// NOT_REACHABLE — exactly the tier a graduated lockfile plugin exists to add.
func buildLockfileTestPlugin(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "commit0-lockfilekit-reachability")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", bin,
		"github.com/commit0-dev/commit0-analyzer/plugins/lockfilekit/testplugin")
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "build lockfilekit test plugin:\n%s", out)
	return bin
}

// graduatedTestAdapter is a fake HasPlugin adapter used to exercise the
// data-driven dispatch seam without graduating any of the seven real ecosystems.
func graduatedTestAdapter() EcosystemAdapter {
	return EcosystemAdapter{
		Ecosystem:     advisory.EcosystemMaven,
		Language:      "java",
		MaxConfidence: ceilingPackage,
		ParseLockfile: func(_ string) ([]ResolvedDep, bool, error) { return nil, true, nil },
		HasPlugin:     true,
		PluginName:    "lockfilekit",
	}
}

// TestLockfilePluginDispatch_PluginPresent proves direction one: when a graduated
// adapter's plugin is present, the host dispatches to it over gRPC, hands it the
// parsed closure via resolved_deps, and the plugin's NOT_REACHABLE verdict
// surfaces. The manifest carries a real SHA-256 pin (no SkipHashCheck), so this
// also exercises the hash-pinned launch path exactly as production does.
func TestLockfilePluginDispatch_PluginPresent(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a plugin binary; skipped in -short")
	}
	bin := buildLockfileTestPlugin(t)
	adapter := graduatedTestAdapter()

	m, ok := buildLockfilePluginManifest(context.Background(), adapter, bin)
	require.True(t, ok)
	require.NotEmpty(t, m.SHA256, "the plugin binary must be hash-pinned")

	reg := host.NewRegistry()
	require.NoError(t, reg.Add(m))

	resolved := resolvedDepsForAdapter(adapter, []ResolvedDep{
		{Name: "org.example:a", Version: "1.0", DepType: "runtime"},
		{Name: "org.example:b", Version: "2.0", DepType: "runtime"},
	})
	req := &commit0v1.AnalyzeRequest{
		Advisories: []*commit0v1.Advisory{
			{Id: "CVE-1", Module: "org.example:a", Ecosystem: commit0v1.Ecosystem_ECOSYSTEM_MAVEN},
		},
		ResolvedDeps:      resolved,
		ClosureIncomplete: false,
	}

	results, runErr := host.Run(context.Background(), reg, req, host.RunOptions{})
	require.NoError(t, runErr)
	require.Len(t, results, 1)

	r := results[0]
	require.NoError(t, r.Err, "the plugin must not crash")
	require.Len(t, r.Findings, 1, "one finding per advisory")

	f := r.Findings[0]
	assert.Equal(t, commit0v1.Confidence_CONFIDENCE_NOT_REACHABLE, f.GetConfidence(),
		"the plugin's NOT_REACHABLE verdict must surface (the tier lockfile parsing cannot prove)")
	assert.Equal(t, "org.example:a", f.GetModule())
	assert.Equal(t, "true", f.GetProperties()["echo"], "the request must have reached the plugin")
	assert.Equal(t, "2", f.GetProperties()["resolved_deps_count"],
		"the host's parsed closure must reach the plugin via resolved_deps (additive minor-2 field)")
	assert.Equal(t, "false", f.GetProperties()["closure_incomplete"])
}

// TestLockfilePluginDispatch_ClosureIncompletePropagates proves the partiality
// signal crosses the wire: a partial closure sets closure_incomplete=true on the
// request, which a real plugin reads to forbid NOT_REACHABLE.
func TestLockfilePluginDispatch_ClosureIncompletePropagates(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a plugin binary; skipped in -short")
	}
	bin := buildLockfileTestPlugin(t)
	adapter := graduatedTestAdapter()
	m, ok := buildLockfilePluginManifest(context.Background(), adapter, bin)
	require.True(t, ok)

	reg := host.NewRegistry()
	require.NoError(t, reg.Add(m))

	req := &commit0v1.AnalyzeRequest{
		Advisories:        []*commit0v1.Advisory{{Id: "CVE-1", Module: "org.example:a"}},
		ResolvedDeps:      resolvedDepsForAdapter(adapter, []ResolvedDep{{Name: "org.example:a", Version: "1.0"}}),
		ClosureIncomplete: true,
	}
	results, runErr := host.Run(context.Background(), reg, req, host.RunOptions{})
	require.NoError(t, runErr)
	require.Len(t, results, 1)
	require.Len(t, results[0].Findings, 1)
	assert.Equal(t, "true", results[0].Findings[0].GetProperties()["closure_incomplete"],
		"closure_incomplete must reach the plugin so it can forbid NOT_REACHABLE over a partial closure")
}

// TestLockfilePluginDispatch_PluginAbsentFallback proves direction two: when a
// graduated adapter's plugin is absent, the host does NOT suppress the direct
// finding — it emits the same PACKAGE_REACHABLE finding it produced before
// graduation. This is the guard against a silent skip (lost advisory coverage).
func TestLockfilePluginDispatch_PluginAbsentFallback(t *testing.T) {
	adapter := graduatedTestAdapter()

	// Plugin absent → pluginWillRun=false → the direct finding is kept.
	assert.False(t, suppressDirectLockfileFinding(adapter, false),
		"a graduated adapter whose plugin is absent must keep its direct finding (fallback)")

	dep := advisoryDep{Module: "org.example:a"}
	adv := &advisory.Advisory{ID: "CVE-1", Aliases: []string{"GHSA-x"}}
	got := newDirectLockfileFinding(adapter, dep, adv)

	// This is byte-for-byte the pre-graduation direct lockfile finding.
	assert.Equal(t, commit0v1.Confidence_CONFIDENCE_PACKAGE_REACHABLE, got.GetConfidence())
	assert.False(t, got.GetIncomplete())
	assert.Equal(t, "org.example:a", got.GetModule())
	assert.Equal(t, "CVE-1", got.GetAdvisory().GetId())
	assert.Equal(t, []string{"GHSA-x"}, got.GetAdvisory().GetAliases())
	assert.Equal(t, "sca", got.GetPillar())
	assert.Equal(t, "java", got.GetLanguage())
}
