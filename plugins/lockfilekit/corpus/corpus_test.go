package corpus_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commit0v1 "github.com/commit0-dev/commit0-analyzer/pkg/contract/commit0v1"
	"github.com/commit0-dev/commit0-analyzer/plugins/lockfilekit"
	"github.com/commit0-dev/commit0-analyzer/plugins/lockfilekit/corpus"
)

// wordParse splits source into letter-run tokens; it always succeeds.
func wordParse(_ string, content []byte) ([]string, bool) {
	nonLetter := func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < 'A' || r > 'Z')
	}
	return strings.FieldsFunc(string(content), nonLetter), true
}

// synthAnalyzer is a minimal but complete plugin analyzer built on the kit: it
// walks project source, then for the advisory package "vulnlib" (which owns the
// namespace token "vulnlib") decides reachability. It proves the harness drives a
// real walk→decide pipeline end-to-end, offline.
func synthAnalyzer(root string) ([]*commit0v1.Finding, error) {
	used, parseIncomplete, err := lockfilekit.Walk(root, lockfilekit.WalkConfig{
		Extensions: []string{".txt"},
		Parse:      wordParse,
	})
	if err != nil {
		return nil, err
	}
	adv := &commit0v1.Advisory{Id: "CVE-SYNTH-1", Module: "vulnlib"}
	f := lockfilekit.Decide(lockfilekit.Decision{
		Advisory:        adv,
		Language:        "synth",
		Ecosystem:       commit0v1.Ecosystem_ECOSYSTEM_UNKNOWN,
		ParseIncomplete: parseIncomplete,
		OwnedNamespaces: lockfilekit.NewSet("vulnlib"),
		UsedTokens:      used,
	})
	return []*commit0v1.Finding{f}, nil
}

func writeFixture(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "app.txt"), []byte(content), 0o644))
	return dir
}

// TestCorpus_SyntheticUnused proves the harness: a project that never references
// the vulnerable package resolves to NOT_REACHABLE.
func TestCorpus_SyntheticUnused(t *testing.T) {
	root := writeFixture(t, "usedlib helper main")
	corpus.Run(t, corpus.Case{
		Name:      "synthetic-unused",
		LocalDir:  root,
		Ecosystem: "synth",
		Expect:    map[string]commit0v1.Confidence{"vulnlib": commit0v1.Confidence_CONFIDENCE_NOT_REACHABLE},
	}, synthAnalyzer)
}

// TestCorpus_SyntheticUsed proves the other direction: a project that references
// the vulnerable package resolves to PACKAGE_REACHABLE.
func TestCorpus_SyntheticUsed(t *testing.T) {
	root := writeFixture(t, "vulnlib helper main")
	corpus.Run(t, corpus.Case{
		Name:      "synthetic-used",
		LocalDir:  root,
		Ecosystem: "synth",
		Expect:    map[string]commit0v1.Confidence{"vulnlib": commit0v1.Confidence_CONFIDENCE_PACKAGE_REACHABLE},
	}, synthAnalyzer)
}

// recorderTB captures harness assertion failures so the harness's own checking
// logic can be verified without failing the enclosing test.
type recorderTB struct {
	errors []string
	fatal  bool
}

func (r *recorderTB) Helper()                   {}
func (r *recorderTB) Logf(string, ...any)       {}
func (r *recorderTB) Errorf(f string, a ...any) { r.errors = append(r.errors, fmt.Sprintf(f, a...)) }
func (r *recorderTB) Fatalf(f string, a ...any) {
	r.fatal = true
	r.errors = append(r.errors, fmt.Sprintf(f, a...))
}

// TestCorpus_MismatchIsReported proves the harness actually checks: a wrong
// expectation must be flagged, not silently passed.
func TestCorpus_MismatchIsReported(t *testing.T) {
	root := writeFixture(t, "usedlib helper") // vulnlib unused → NOT_REACHABLE
	rec := &recorderTB{}
	corpus.Run(rec, corpus.Case{
		Name:      "mismatch",
		LocalDir:  root,
		Ecosystem: "synth",
		// Wrong: claims PACKAGE_REACHABLE though the analyzer yields NOT_REACHABLE.
		Expect: map[string]commit0v1.Confidence{"vulnlib": commit0v1.Confidence_CONFIDENCE_PACKAGE_REACHABLE},
	}, synthAnalyzer)
	require.NotEmpty(t, rec.errors, "the harness must report a confidence mismatch")
	assert.Contains(t, strings.Join(rec.errors, "\n"), "vulnlib")
}

// TestCorpus_MissingPackageIsReported proves the harness flags an expected
// package that produced no finding (a silently-dropped advisory).
func TestCorpus_MissingPackageIsReported(t *testing.T) {
	root := writeFixture(t, "anything")
	rec := &recorderTB{}
	corpus.Run(rec, corpus.Case{
		Name:      "missing",
		LocalDir:  root,
		Ecosystem: "synth",
		Expect:    map[string]commit0v1.Confidence{"absent-pkg": commit0v1.Confidence_CONFIDENCE_NOT_REACHABLE},
	}, synthAnalyzer)
	require.NotEmpty(t, rec.errors, "an expected package with no finding must be reported")
	assert.Contains(t, strings.Join(rec.errors, "\n"), "absent-pkg")
}
