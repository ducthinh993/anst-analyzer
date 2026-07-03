package pub

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commit0v1 "github.com/commit0-dev/commit0-analyzer/pkg/contract/commit0v1"
)

// ── fixture helpers ───────────────────────────────────────────────────────────

func mkfile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
}

// projectRoot writes a project at <tmp>/app whose lib imports the given packages.
func projectRoot(t *testing.T, tmp string, imports ...string) string {
	t.Helper()
	root := filepath.Join(tmp, "app")
	var src strings.Builder
	for _, imp := range imports {
		fmt.Fprintf(&src, "import 'package:%s/%s.dart';\n", imp, imp)
	}
	src.WriteString("void main() {}\n")
	mkfile(t, filepath.Join(root, "lib", "app.dart"), src.String())
	return root
}

// depDir writes a dependency package under <tmp>/cache/<name> whose lib imports
// the given packages, returning the package root directory.
func depDir(t *testing.T, tmp, name string, imports ...string) string {
	t.Helper()
	root := filepath.Join(tmp, "cache", name)
	var src strings.Builder
	for _, imp := range imports {
		fmt.Fprintf(&src, "import 'package:%s/%s.dart';\n", imp, imp)
	}
	src.WriteString("class X {}\n")
	mkfile(t, filepath.Join(root, "lib", name+".dart"), src.String())
	return root
}

// writePackageConfig writes .dart_tool/package_config.json mapping each package
// name to a source root directory (via an absolute file:// rootUri).
func writePackageConfig(t *testing.T, root string, dirs map[string]string) {
	t.Helper()
	type entry struct {
		Name       string `json:"name"`
		RootURI    string `json:"rootUri"`
		PackageURI string `json:"packageUri"`
	}
	var pc struct {
		ConfigVersion int     `json:"configVersion"`
		Packages      []entry `json:"packages"`
	}
	pc.ConfigVersion = 2
	for name, dir := range dirs {
		abs, err := filepath.Abs(dir)
		require.NoError(t, err)
		pc.Packages = append(pc.Packages, entry{Name: name, RootURI: "file://" + abs, PackageURI: "lib/"})
	}
	data, err := json.Marshal(pc)
	require.NoError(t, err)
	mkfile(t, filepath.Join(root, ".dart_tool", "package_config.json"), string(data))
}

func adv(id, module string) *commit0v1.Advisory {
	return &commit0v1.Advisory{Id: id, Module: module}
}

func run(t *testing.T, root string, closureIncomplete bool, advs ...*commit0v1.Advisory) map[string]*commit0v1.Finding {
	t.Helper()
	a := &Analyzer{Root: root, Advisories: advs, ClosureIncomplete: closureIncomplete}
	out := make(map[string]*commit0v1.Finding)
	for _, f := range a.Analyze() {
		out[f.GetModule()] = f
	}
	return out
}

func assertUnknownIncomplete(t *testing.T, f *commit0v1.Finding) {
	t.Helper()
	require.NotNil(t, f)
	assert.Equal(t, commit0v1.Confidence_CONFIDENCE_UNKNOWN, f.GetConfidence())
	assert.True(t, f.GetIncomplete(), "UNKNOWN must carry Incomplete=true (partiality signal)")
	assert.Equal(t, "true", f.GetProperties()["synthetic"], "UNKNOWN must carry the synthetic marker")
}

// ── unit: package_config resolution ───────────────────────────────────────────

func TestResolvePackageDirs(t *testing.T) {
	dartTool := filepath.FromSlash("/proj/.dart_tool")

	// file:// rootUri resolves to an absolute root; source is root/packageUri.
	rootFoo := resolvePackageRoot(dartTool, "file:///abs/foo")
	assert.Equal(t, filepath.FromSlash("/abs/foo"), rootFoo)
	assert.Equal(t, filepath.FromSlash("/abs/foo/lib"), resolveSourceDir(rootFoo, "lib/"))

	// Relative rootUri resolves against the .dart_tool dir.
	rootBar := resolvePackageRoot(dartTool, "../bar")
	assert.Equal(t, filepath.Join(dartTool, filepath.FromSlash("../bar")), rootBar)
	// Empty packageUri defaults to lib/.
	assert.Equal(t, filepath.Join(dartTool, filepath.FromSlash("../bar/lib")), resolveSourceDir(rootBar, ""))
}

func TestLoadPackageConfig_AbsentIsIncomplete(t *testing.T) {
	_, ok := loadPackageConfig(t.TempDir())
	assert.False(t, ok, "absent package_config.json → transitive closure cannot be completed")
}

// ── unit: transitive closure ──────────────────────────────────────────────────

func TestBuildClosure_TransitiveFixpoint(t *testing.T) {
	tmp := t.TempDir()
	root := projectRoot(t, tmp, "a")
	dirA := depDir(t, tmp, "a", "b") // a imports b
	dirB := depDir(t, tmp, "b")      // b is a leaf
	writePackageConfig(t, root, map[string]string{"app": root, "a": dirA, "b": dirB})

	c := buildClosure(root)
	assert.True(t, c.Used.Has("a"))
	assert.True(t, c.Used.Has("b"), "a transitively-imported package must be in the used closure")
	assert.False(t, c.Frontier.Present())
	assert.False(t, c.ParseIncomplete)
	assert.False(t, c.TransitiveIncomplete)
}

// ── decision matrix ───────────────────────────────────────────────────────────

func TestDecide_UsedDirect_PackageReachable(t *testing.T) {
	tmp := t.TempDir()
	root := projectRoot(t, tmp, "a")
	dirA := depDir(t, tmp, "a")
	writePackageConfig(t, root, map[string]string{"app": root, "a": dirA})

	got := run(t, root, false, adv("CVE-1", "a"))
	assert.Equal(t, commit0v1.Confidence_CONFIDENCE_PACKAGE_REACHABLE, got["a"].GetConfidence())
}

// The load-bearing false-NOT_REACHABLE guard: a package reached only through
// another package must be PACKAGE_REACHABLE, never NOT_REACHABLE.
func TestDecide_UsedTransitive_PackageReachable(t *testing.T) {
	tmp := t.TempDir()
	root := projectRoot(t, tmp, "a")
	dirA := depDir(t, tmp, "a", "b")
	dirB := depDir(t, tmp, "b")
	writePackageConfig(t, root, map[string]string{"app": root, "a": dirA, "b": dirB})

	got := run(t, root, false, adv("CVE-B", "b"))
	require.NotNil(t, got["b"])
	assert.Equal(t, commit0v1.Confidence_CONFIDENCE_PACKAGE_REACHABLE, got["b"].GetConfidence(),
		"a transitively-used package must not be suppressed as NOT_REACHABLE")
}

func TestDecide_UnusedComplete_NotReachable(t *testing.T) {
	tmp := t.TempDir()
	root := projectRoot(t, tmp, "a")
	dirA := depDir(t, tmp, "a")
	dirVuln := depDir(t, tmp, "vulnerable")
	writePackageConfig(t, root, map[string]string{"app": root, "a": dirA, "vulnerable": dirVuln})

	got := run(t, root, false, adv("CVE-V", "vulnerable"))
	f := got["vulnerable"]
	require.NotNil(t, f)
	assert.Equal(t, commit0v1.Confidence_CONFIDENCE_NOT_REACHABLE, f.GetConfidence())
	assert.False(t, f.GetIncomplete())
	assert.Contains(t, f.GetProperties()["reason"], "used-import closure")
	assert.NotEmpty(t, f.GetProperties()["used_closure_size"], "NOT_REACHABLE must carry closure-size evidence")
}

func TestDecide_MirrorsFrontier_Unknown(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "app")
	mkfile(t, filepath.Join(root, "lib", "app.dart"),
		"import 'dart:mirrors';\nimport 'package:a/a.dart';\nvoid main() {}\n")
	dirA := depDir(t, tmp, "a")
	writePackageConfig(t, root, map[string]string{"app": root, "a": dirA})

	got := run(t, root, false, adv("CVE-V", "vulnerable"), adv("CVE-A", "a"))
	assertUnknownIncomplete(t, got["vulnerable"])
	assert.Contains(t, got["vulnerable"].GetProperties()["reason"], "mirrors")
	// A statically-imported package stays PACKAGE_REACHABLE even under a frontier.
	assert.Equal(t, commit0v1.Confidence_CONFIDENCE_PACKAGE_REACHABLE, got["a"].GetConfidence())
}

func TestDecide_SpawnUriFrontier_Unknown(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "app")
	mkfile(t, filepath.Join(root, "lib", "app.dart"),
		"import 'dart:isolate';\nvoid go() { Isolate.spawnUri(u, [], null); }\n")
	writePackageConfig(t, root, map[string]string{"app": root})

	got := run(t, root, false, adv("CVE-V", "vulnerable"))
	assertUnknownIncomplete(t, got["vulnerable"])
	assert.Contains(t, got["vulnerable"].GetProperties()["reason"], "spawnUri")
}

func TestDecide_BuildHookFrontier_Unknown(t *testing.T) {
	tmp := t.TempDir()
	root := projectRoot(t, tmp, "a")
	dirA := depDir(t, tmp, "a")
	mkfile(t, filepath.Join(root, "build.dart"), "void main() {}\n")
	writePackageConfig(t, root, map[string]string{"app": root, "a": dirA})

	got := run(t, root, false, adv("CVE-V", "vulnerable"))
	assertUnknownIncomplete(t, got["vulnerable"])
	assert.Contains(t, got["vulnerable"].GetProperties()["reason"], "build hook")
}

// A build hook in a DEPENDENCY (not the project root) can synthesize
// cross-package imports the static walk never sees, so it must forbid
// NOT_REACHABLE project-wide — the dependency hook lives at the dep root, not
// under its lib/, so the source walk alone would miss it.
func TestDecide_DependencyBuildHookFrontier_Unknown(t *testing.T) {
	tmp := t.TempDir()
	root := projectRoot(t, tmp, "a")
	dirA := depDir(t, tmp, "a")
	mkfile(t, filepath.Join(dirA, "hook", "build.dart"), "void main() {}\n")
	writePackageConfig(t, root, map[string]string{"app": root, "a": dirA})

	got := run(t, root, false, adv("CVE-V", "vulnerable"), adv("CVE-A", "a"))
	assertUnknownIncomplete(t, got["vulnerable"])
	assert.Contains(t, got["vulnerable"].GetProperties()["reason"], "build hook")
	// The imported dependency itself remains a definitive positive.
	assert.Equal(t, commit0v1.Confidence_CONFIDENCE_PACKAGE_REACHABLE, got["a"].GetConfidence())
}

func TestDecide_AbsentGeneratedPart_Unknown(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "app")
	mkfile(t, filepath.Join(root, "lib", "app.dart"),
		"part 'app.g.dart';\nimport 'package:a/a.dart';\nvoid main() {}\n")
	dirA := depDir(t, tmp, "a")
	writePackageConfig(t, root, map[string]string{"app": root, "a": dirA})

	got := run(t, root, false, adv("CVE-V", "vulnerable"))
	assertUnknownIncomplete(t, got["vulnerable"])
}

func TestDecide_PresentGeneratedPart_NotReachable(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "app")
	mkfile(t, filepath.Join(root, "lib", "app.dart"),
		"part 'app.g.dart';\nimport 'package:a/a.dart';\nvoid main() {}\n")
	mkfile(t, filepath.Join(root, "lib", "app.g.dart"), "// generated, present\n")
	dirA := depDir(t, tmp, "a")
	writePackageConfig(t, root, map[string]string{"app": root, "a": dirA})

	got := run(t, root, false, adv("CVE-V", "vulnerable"))
	assert.Equal(t, commit0v1.Confidence_CONFIDENCE_NOT_REACHABLE, got["vulnerable"].GetConfidence(),
		"a present generated part is normal source; it must not force UNKNOWN")
}

func TestDecide_NoPackageConfig_TransitiveIncomplete(t *testing.T) {
	tmp := t.TempDir()
	root := projectRoot(t, tmp, "a") // imports a directly; no .dart_tool written

	got := run(t, root, false, adv("CVE-A", "a"), adv("CVE-V", "vulnerable"))
	// Directly imported → still a definitive positive.
	assert.Equal(t, commit0v1.Confidence_CONFIDENCE_PACKAGE_REACHABLE, got["a"].GetConfidence())
	// Unproven (cannot complete transitive walk) → UNKNOWN, never NOT_REACHABLE.
	assertUnknownIncomplete(t, got["vulnerable"])
}

func TestDecide_MissingDepSourceDir_TransitiveIncomplete(t *testing.T) {
	tmp := t.TempDir()
	root := projectRoot(t, tmp, "a")
	// package_config points package a at a directory that does not exist.
	writePackageConfig(t, root, map[string]string{
		"app": root,
		"a":   filepath.Join(tmp, "cache", "missing-a"),
	})

	got := run(t, root, false, adv("CVE-V", "vulnerable"))
	assertUnknownIncomplete(t, got["vulnerable"])
}

func TestDecide_ClosureIncomplete_ForbidsNotReachable(t *testing.T) {
	tmp := t.TempDir()
	root := projectRoot(t, tmp, "a")
	dirA := depDir(t, tmp, "a")
	writePackageConfig(t, root, map[string]string{"app": root, "a": dirA})

	// Host says the lockfile closure is partial → no NOT_REACHABLE at all.
	got := run(t, root, true, adv("CVE-V", "vulnerable"), adv("CVE-A", "a"))
	assertUnknownIncomplete(t, got["vulnerable"])
	// A positive static reference is still definitive.
	assert.Equal(t, commit0v1.Confidence_CONFIDENCE_PACKAGE_REACHABLE, got["a"].GetConfidence())
}

// Every advisory the host sends must return exactly one finding (a silently
// dropped advisory is the same cardinal sin as a false NOT_REACHABLE).
func TestAnalyze_EveryAdvisoryYieldsExactlyOneFinding(t *testing.T) {
	tmp := t.TempDir()
	root := projectRoot(t, tmp, "a")
	dirA := depDir(t, tmp, "a")
	writePackageConfig(t, root, map[string]string{"app": root, "a": dirA})

	advs := []*commit0v1.Advisory{adv("CVE-A", "a"), adv("CVE-V", "vulnerable"), adv("CVE-W", "another")}
	a := &Analyzer{Root: root, Advisories: advs}
	findings := a.Analyze()
	require.Len(t, findings, len(advs))
}
