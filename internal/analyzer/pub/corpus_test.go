package pub

import (
	"path/filepath"
	"testing"

	commit0v1 "github.com/commit0-dev/commit0-analyzer/pkg/contract/commit0v1"
	"github.com/commit0-dev/commit0-analyzer/internal/analyzer/lockfilekit/corpus"
)

// analyzerFor adapts engine.Analyzer to the corpus.Analyzer shape, baking in the
// advisory set the case expects verdicts for.
func analyzerFor(advs ...*commit0v1.Advisory) corpus.Analyzer {
	return func(root string) ([]*commit0v1.Finding, error) {
		a := &Analyzer{Root: root, Advisories: advs}
		return a.Analyze(), nil
	}
}

// TestCorpus_UsedAndUnused proves the pipeline end-to-end through the shared
// corpus harness on a hermetic Dart fixture: a used dependency resolves to
// PACKAGE_REACHABLE and a provably-unused one to NOT_REACHABLE.
func TestCorpus_UsedAndUnused(t *testing.T) {
	tmp := t.TempDir()
	root := projectRoot(t, tmp, "http")   // project imports package:http
	dirHTTP := depDir(t, tmp, "http")      // http is a leaf
	dirEvil := depDir(t, tmp, "evil")      // present in closure, never imported
	writePackageConfig(t, root, map[string]string{"app": root, "http": dirHTTP, "evil": dirEvil})

	corpus.Run(t, corpus.Case{
		Name:      "pub-used-and-unused",
		LocalDir:  root,
		Ecosystem: "pub",
		Expect: map[string]commit0v1.Confidence{
			"http": commit0v1.Confidence_CONFIDENCE_PACKAGE_REACHABLE,
			"evil": commit0v1.Confidence_CONFIDENCE_NOT_REACHABLE,
		},
	}, analyzerFor(adv("CVE-HTTP", "http"), adv("CVE-EVIL", "evil")))
}

// TestCorpus_FrontierSuppressesNotReachable proves that a dynamism frontier
// (here dart:mirrors) forbids NOT_REACHABLE for an unused package (→ UNKNOWN)
// while a statically-imported package stays PACKAGE_REACHABLE.
func TestCorpus_FrontierSuppressesNotReachable(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "app")
	mkfile(t, filepath.Join(root, "lib", "app.dart"),
		"import 'dart:mirrors';\nimport 'package:http/http.dart';\nvoid main() {}\n")
	dirHTTP := depDir(t, tmp, "http")
	writePackageConfig(t, root, map[string]string{"app": root, "http": dirHTTP})

	corpus.Run(t, corpus.Case{
		Name:      "pub-frontier-mirrors",
		LocalDir:  root,
		Ecosystem: "pub",
		Expect: map[string]commit0v1.Confidence{
			"evil": commit0v1.Confidence_CONFIDENCE_UNKNOWN,
			"http": commit0v1.Confidence_CONFIDENCE_PACKAGE_REACHABLE,
		},
	}, analyzerFor(adv("CVE-EVIL", "evil"), adv("CVE-HTTP", "http")))
}
