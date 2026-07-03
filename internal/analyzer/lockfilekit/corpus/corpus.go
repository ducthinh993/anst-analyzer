// Package corpus is the table-driven real-repo test harness shared by every
// lockfile-ecosystem reachability plugin. A plugin's per-plugin gate is not
// "green unit tests" — it is "on a real public repo, a provably-unused vulnerable
// dependency resolves to NOT_REACHABLE and a used one resolves to
// PACKAGE_REACHABLE". This harness encodes exactly that: a Case pins a repo +
// commit + per-package expected confidence, the harness checks the repo out
// (shallow, read-only) into a cache, runs the plugin's analyzer over it, and
// asserts the per-package verdicts.
//
// A synthetic Case (LocalDir set, RepoURL empty) skips the clone and runs
// against a local fixture directory — used here to prove the harness itself and,
// in ecosystem phases, for offline fixtures alongside the real repos.
package corpus

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	commit0v1 "github.com/commit0-dev/commit0-analyzer/pkg/contract/commit0v1"
)

// TB is the subset of testing.TB the harness needs, so corpus.go stays free of a
// direct testing import while accepting a *testing.T at the call site.
type TB interface {
	Helper()
	Logf(format string, args ...any)
	Errorf(format string, args ...any)
	Fatalf(format string, args ...any)
}

// Analyzer runs a plugin's reachability analysis over a checked-out project root
// and returns one Finding per advisory package. Each ecosystem plugin adapts its
// standalone entrypoint into this shape for the harness.
type Analyzer func(root string) ([]*commit0v1.Finding, error)

// Case is one real-repo (or synthetic) expectation.
type Case struct {
	// Name identifies the case in test output.
	Name string

	// RepoURL is the git URL to clone. Empty when LocalDir is set.
	RepoURL string

	// Commit is the pinned commit SHA to check out (required with RepoURL so the
	// expectation is reproducible against a frozen tree).
	Commit string

	// LocalDir is a local fixture directory analyzed directly (no clone). When
	// set, RepoURL/Commit are ignored.
	LocalDir string

	// Ecosystem is a human label for output (e.g. "pub", "hex").
	Ecosystem string

	// Expect maps a package/module name to the confidence the analyzer must emit
	// for it. Every entry must be matched exactly; an unlisted package is ignored.
	Expect map[string]commit0v1.Confidence
}

// Run checks the case out, runs the analyzer, and asserts every Expect entry.
func Run(t TB, c Case, a Analyzer) {
	t.Helper()

	root, cleanup, err := c.checkout()
	if err != nil {
		t.Fatalf("corpus %q: checkout: %v", c.Name, err)
		return
	}
	if cleanup != nil {
		defer cleanup()
	}

	findings, err := a(root)
	if err != nil {
		t.Fatalf("corpus %q: analyze %s: %v", c.Name, root, err)
		return
	}

	got := indexByModule(t, c, findings)
	for pkg, want := range c.Expect {
		gotConf, ok := got[pkg]
		if !ok {
			t.Errorf("corpus %q: no finding for package %q (want %s)", c.Name, pkg, want)
			continue
		}
		if gotConf != want {
			t.Errorf("corpus %q: package %q: got %s, want %s", c.Name, pkg, gotConf, want)
		}
	}
}

// indexByModule builds a module→confidence map from findings, flagging a plugin
// that emits conflicting confidences for the same module (a soundness bug).
func indexByModule(t TB, c Case, findings []*commit0v1.Finding) map[string]commit0v1.Confidence {
	t.Helper()
	got := make(map[string]commit0v1.Confidence, len(findings))
	for _, f := range findings {
		mod := f.GetModule()
		if prev, ok := got[mod]; ok && prev != f.GetConfidence() {
			t.Errorf("corpus %q: module %q has conflicting confidences %s and %s",
				c.Name, mod, prev, f.GetConfidence())
		}
		got[mod] = f.GetConfidence()
	}
	return got
}

// checkout returns the project root to analyze plus an optional cleanup. A
// synthetic case returns its LocalDir unchanged; a repo case shallow-clones into
// a content-addressed cache (reused across runs) and checks out the pinned commit.
func (c Case) checkout() (root string, cleanup func(), err error) {
	if c.LocalDir != "" {
		return c.LocalDir, nil, nil
	}
	if c.RepoURL == "" || c.Commit == "" {
		return "", nil, fmt.Errorf("case %q: RepoURL and Commit are required when LocalDir is unset", c.Name)
	}

	cacheDir, err := cloneCacheDir(c.RepoURL, c.Commit)
	if err != nil {
		return "", nil, err
	}
	// A populated cache is reused as-is (read-only): the pinned commit makes the
	// tree immutable, so a prior checkout is authoritative.
	if entries, statErr := os.ReadDir(cacheDir); statErr == nil && len(entries) > 0 {
		return cacheDir, nil, nil
	}
	if err := shallowClone(c.RepoURL, c.Commit, cacheDir); err != nil {
		return "", nil, err
	}
	return cacheDir, nil, nil
}

// cloneCacheDir returns a content-addressed cache directory for a repo+commit
// under os.UserCacheDir()/commit0-analyzer/corpus/, creating its parent.
func cloneCacheDir(repoURL, commit string) (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("locate user cache dir: %w", err)
	}
	dir := filepath.Join(base, "commit0-analyzer", "corpus", sanitize(repoURL)+"@"+commit)
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return "", fmt.Errorf("create corpus cache parent: %w", err)
	}
	return dir, nil
}

// shallowClone fetches a single commit into dir without checking out working
// history: git init + remote add + fetch --depth 1 <commit> + checkout FETCH_HEAD.
// It never runs repo build scripts — only git plumbing.
func shallowClone(repoURL, commit, dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create clone dir: %w", err)
	}
	steps := [][]string{
		{"init", "-q"},
		{"remote", "add", "origin", repoURL},
		{"fetch", "--depth", "1", "-q", "origin", commit},
		{"checkout", "-q", "FETCH_HEAD"},
	}
	for _, args := range steps {
		cmd := exec.CommandContext(context.Background(), "git", append([]string{"-C", dir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			_ = os.RemoveAll(dir) // don't leave a half-cloned tree that looks cached
			return fmt.Errorf("git %v: %w\n%s", args, err, out)
		}
	}
	return nil
}

// sanitize turns a repo URL into a filesystem-safe cache segment.
func sanitize(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			out = append(out, r)
		default:
			out = append(out, '_')
		}
	}
	return string(out)
}
