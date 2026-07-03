package pub

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commit0v1 "github.com/commit0-dev/commit0-analyzer/pkg/contract/commit0v1"
)

// TestRealRepo_DartHttp is a best-effort empirical gate: it clones a pinned
// commit of dart-lang/http and runs the analyzer over pkgs/http WITHOUT running
// `dart pub get`, so no .dart_tool/package_config.json exists in the tree.
//
// It asserts the two invariants that matter on real source:
//   - a directly-imported third-party package resolves to PACKAGE_REACHABLE, and
//   - an absent package is NEVER suppressed as NOT_REACHABLE when the transitive
//     closure cannot be completed (the cardinal-sin guard on real code).
//
// Demonstrating a real NOT_REACHABLE on a public repo would require a resolved
// package_config.json (i.e. a `dart pub get` had been run and the pub cache
// present), which a bare clone lacks and which this plugin must never produce
// itself (running pub executes build hooks — arbitrary code execution). The
// hermetic corpus tests cover the NOT_REACHABLE path with a synthesized closure.
//
// Gated behind COMMIT0_CORPUS_NETWORK because it needs network + git.
func TestRealRepo_DartHttp(t *testing.T) {
	if os.Getenv("COMMIT0_CORPUS_NETWORK") == "" {
		t.Skip("set COMMIT0_CORPUS_NETWORK=1 to run the network-dependent real-repo gate")
	}
	const (
		repoURL = "https://github.com/dart-lang/http"
		commit  = "5d94ef52582867e077bf41c3fa20fb8b1d1d834e"
		subdir  = "pkgs/http"
	)
	clone := t.TempDir()
	shallowClone(t, clone, repoURL, commit)
	root := filepath.Join(clone, subdir)
	require.DirExists(t, root)

	a := &Analyzer{
		Root: root,
		Advisories: []*commit0v1.Advisory{
			adv("ADV-http_parser", "http_parser"),
			adv("ADV-meta", "meta"),
			adv("ADV-absent", "commit0_absent_pkg_xyz"),
		},
	}
	got := make(map[string]*commit0v1.Finding)
	for _, f := range a.Analyze() {
		got[f.GetModule()] = f
	}

	require.NotNil(t, got["http_parser"])
	require.NotNil(t, got["meta"])
	require.NotNil(t, got["commit0_absent_pkg_xyz"])

	assert.Equal(t, commit0v1.Confidence_CONFIDENCE_PACKAGE_REACHABLE, got["http_parser"].GetConfidence(),
		"a directly-imported third-party package must be PACKAGE_REACHABLE")
	assert.Equal(t, commit0v1.Confidence_CONFIDENCE_PACKAGE_REACHABLE, got["meta"].GetConfidence())
	assert.NotEqual(t, commit0v1.Confidence_CONFIDENCE_NOT_REACHABLE, got["commit0_absent_pkg_xyz"].GetConfidence(),
		"no false NOT_REACHABLE without a resolved package_config-backed closure")
}

// shallowClone fetches a single pinned commit into dir using only git plumbing
// (never any repo build script).
func shallowClone(t *testing.T, dir, repoURL, commit string) {
	t.Helper()
	steps := [][]string{
		{"init", "-q"},
		{"remote", "add", "origin", repoURL},
		{"fetch", "--depth", "1", "-q", "origin", commit},
		{"checkout", "-q", "FETCH_HEAD"},
	}
	for _, args := range steps {
		cmd := exec.CommandContext(context.Background(), "git", append([]string{"-C", dir}, args...)...)
		out, err := cmd.CombinedOutput()
		require.NoErrorf(t, err, "git %v: %s", args, out)
	}
}
