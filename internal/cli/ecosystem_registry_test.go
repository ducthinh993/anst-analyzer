package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/commit0-dev/commit0-analyzer/internal/advisory"
)

// ── registry helpers ──────────────────────────────────────────────────────────

// withCleanRegistry saves the global registry, clears it, calls fn, then
// restores the original state. Use in tests that register temporary adapters
// to avoid leaking state into other test cases.
func withCleanRegistry(t *testing.T, fn func()) {
	t.Helper()
	saved := ecosystemRegistry
	ecosystemRegistry = nil
	defer func() { ecosystemRegistry = saved }()
	fn()
}

// ── RegisterEcosystemAdapter + EcosystemAdapters ─────────────────────────────

// TestRegisterEcosystemAdapter_SingleAdapter verifies that a registered adapter
// appears in the EcosystemAdapters snapshot.
func TestRegisterEcosystemAdapter_SingleAdapter(t *testing.T) {
	withCleanRegistry(t, func() {
		a := EcosystemAdapter{
			Ecosystem:     advisory.EcosystemMaven,
			Language:      "java",
			DetectFiles:   []string{"pom.xml"},
			MaxConfidence: ceilingPackage,
			ParseLockfile: func(_ string) ([]ResolvedDep, bool, error) { return nil, true, nil },
		}
		RegisterEcosystemAdapter(a)

		adapters := EcosystemAdapters()
		require.Len(t, adapters, 1, "exactly one adapter should be registered")
		assert.Equal(t, advisory.EcosystemMaven, adapters[0].Ecosystem)
		assert.Equal(t, "java", adapters[0].Language)
		assert.Equal(t, []string{"pom.xml"}, adapters[0].DetectFiles)
	})
}

// TestRegisterEcosystemAdapter_MultipleAdapters verifies that multiple adapters
// sharing the same Language are registered in insertion order. (Multiple
// adapters per Language is permitted by the registry; useful when a single
// language ecosystem has several lockfile variants, e.g. Maven and Gradle once
// both have real parsers.)
func TestRegisterEcosystemAdapter_MultipleAdapters(t *testing.T) {
	withCleanRegistry(t, func() {
		RegisterEcosystemAdapter(EcosystemAdapter{Ecosystem: "Maven-A", Language: "java", ParseLockfile: func(_ string) ([]ResolvedDep, bool, error) { return nil, true, nil }})
		RegisterEcosystemAdapter(EcosystemAdapter{Ecosystem: "Maven-B", Language: "java", ParseLockfile: func(_ string) ([]ResolvedDep, bool, error) { return nil, true, nil }})
		RegisterEcosystemAdapter(EcosystemAdapter{Ecosystem: "Maven-C", Language: "java", ParseLockfile: func(_ string) ([]ResolvedDep, bool, error) { return nil, true, nil }})

		adapters := EcosystemAdapters()
		require.Len(t, adapters, 3)
		assert.Equal(t, "Maven-A", adapters[0].Ecosystem)
		assert.Equal(t, "Maven-B", adapters[1].Ecosystem)
		assert.Equal(t, "Maven-C", adapters[2].Ecosystem)
	})
}

// TestEcosystemAdapters_ReturnsSnapshot verifies that mutating the returned slice
// does not affect the registry (the returned value is a copy, not a reference).
func TestEcosystemAdapters_ReturnsSnapshot(t *testing.T) {
	withCleanRegistry(t, func() {
		RegisterEcosystemAdapter(EcosystemAdapter{
			Ecosystem:     "Maven-Original",
			Language:      "java",
			ParseLockfile: func(_ string) ([]ResolvedDep, bool, error) { return nil, true, nil },
		})

		snap1 := EcosystemAdapters()
		require.Len(t, snap1, 1)

		// Mutate the snapshot.
		snap1[0].Ecosystem = "Maven-Mutated"

		// A fresh call must reflect the original registry, not the mutation.
		snap2 := EcosystemAdapters()
		require.Len(t, snap2, 1)
		assert.Equal(t, "Maven-Original", snap2[0].Ecosystem,
			"EcosystemAdapters must return a copy; mutations must not affect the registry")
	})
}

// TestLockfileAdapters_OnlyParseLockfileBacked verifies that lockfileAdapters
// returns exactly the adapters whose closure is resolved by static lockfile
// parsing (ParseLockfile != nil), excluding plugin-backed ecosystems.
func TestLockfileAdapters_OnlyParseLockfileBacked(t *testing.T) {
	withCleanRegistry(t, func() {
		// A plugin-backed entry (ParseLockfile nil) plus a lockfile-static entry.
		RegisterEcosystemAdapter(EcosystemAdapter{Ecosystem: advisory.EcosystemGo, Language: "go", MaxConfidence: ceilingSymbol})
		RegisterEcosystemAdapter(EcosystemAdapter{
			Ecosystem:     advisory.EcosystemMaven,
			Language:      "java",
			MaxConfidence: ceilingPackage,
			ParseLockfile: func(_ string) ([]ResolvedDep, bool, error) { return nil, true, nil },
		})

		lockfile := lockfileAdapters()
		require.Len(t, lockfile, 1, "only the ParseLockfile-backed adapter must be returned")
		assert.Equal(t, "java", lockfile[0].Language,
			"plugin-backed (nil ParseLockfile) adapters must be excluded from the lockfile set")
	})
}

// ── ecosystems set (active / set / clear / any / clone) ───────────────────────

// TestEcosystems_ActiveSetClear verifies the fundamental set operations: a
// language is inactive until set, active after set, inactive again after clear.
func TestEcosystems_ActiveSetClear(t *testing.T) {
	e := make(ecosystems)
	assert.False(t, e.active("java"), "precondition: java inactive in empty set")
	e.set("java")
	assert.True(t, e.active("java"), "set(java) → active(java) must be true")
	e.clear("java")
	assert.False(t, e.active("java"), "clear(java) → active(java) must be false")
}

// TestEcosystems_ActiveUnknownKey verifies that an unregistered language key and
// the empty key are inactive regardless of other detected ecosystems (no
// cross-contamination; --language is a narrowing filter, never activation).
func TestEcosystems_ActiveUnknownKey(t *testing.T) {
	eco := ecosystems{"go": true, "js": true, "rust": true, "python": true, "java": true}
	assert.False(t, eco.active("nuget"), "an unregistered key must be inactive even when other ecosystems are detected")
	assert.False(t, eco.active(""), "the empty key must be inactive")
}

// TestEcosystems_ClearDoesNotAffectOthers verifies that clearing one language
// does not disturb the others.
func TestEcosystems_ClearDoesNotAffectOthers(t *testing.T) {
	e := ecosystems{"go": true, "js": true, "rust": true, "python": true, "java": true}
	e.clear("java")
	assert.True(t, e.active("go"), "Go must be unaffected by clear(java)")
	assert.True(t, e.active("js"), "JS must be unaffected by clear(java)")
	assert.True(t, e.active("rust"), "Rust must be unaffected by clear(java)")
	assert.True(t, e.active("python"), "Python must be unaffected by clear(java)")
	assert.False(t, e.active("java"), "Java must be cleared")
}

// TestEcosystems_Any verifies the emptiness predicate used by the nothing-to-scan
// guard.
func TestEcosystems_Any(t *testing.T) {
	assert.False(t, make(ecosystems).any(), "empty set → any() must be false")
	assert.True(t, ecosystems{"go": true}.any(), "one entry → any() must be true")
}

// TestEcosystems_CloneIsIndependent verifies that clone returns an independent
// copy. This guards the unsupportedEco aliasing hazard: ecosystems is a map
// (reference type), so a plain assignment would alias and reducing the copy would
// corrupt the original set that later plugin registration reads.
func TestEcosystems_CloneIsIndependent(t *testing.T) {
	orig := ecosystems{"go": true, "rust": true}
	cp := orig.clone()
	cp.clear("rust")
	cp.set("java")

	assert.True(t, orig.active("rust"), "clearing the clone must not clear the original")
	assert.False(t, orig.active("java"), "adding to the clone must not add to the original")
	assert.False(t, cp.active("rust"), "the clone reflects its own mutation")
	assert.True(t, cp.active("java"), "the clone reflects its own mutation")
}

// ── isKnownLanguage ───────────────────────────────────────────────────────────

// TestIsKnownLanguage_ValidValues verifies that every supported --language value
// is recognised.
func TestIsKnownLanguage_ValidValues(t *testing.T) {
	for _, lang := range []string{
		"go", "js", "rust", "python",
		"java", "dotnet", "php", "ruby", "elixir", "dart", "swift",
	} {
		assert.True(t, isKnownLanguage(lang), lang+" must be a known --language value")
	}
}

// TestIsKnownLanguage_UnknownValues verifies that unregistered values (including
// OSV ecosystem names and the empty string) are not accepted --language values.
func TestIsKnownLanguage_UnknownValues(t *testing.T) {
	assert.False(t, isKnownLanguage("nuget"), "nuget is an OSV ecosystem name, not a --language value")
	assert.False(t, isKnownLanguage("kotlin"), "unregistered language must return false")
	assert.False(t, isKnownLanguage(""), "empty string is not a known language")
}

// ── Java adapter (registered by init()) ──────────────────────────────────────

// TestJavaAdapter_IsRegistered verifies that the Java adapter is present in the
// global registry after package init.
func TestJavaAdapter_IsRegistered(t *testing.T) {
	var javaAdapter *EcosystemAdapter
	for _, a := range EcosystemAdapters() {
		if a.Language == "java" {
			a := a // capture
			javaAdapter = &a
			break
		}
	}
	require.NotNil(t, javaAdapter, "Java adapter must be registered by init()")
	assert.Equal(t, advisory.EcosystemMaven, javaAdapter.Ecosystem,
		"Java adapter must declare the Maven OSV ecosystem")
}

// TestJavaAdapter_DetectFiles verifies that the Java adapter lists the expected
// Maven and Gradle manifest files for zero-config auto-detection.
func TestJavaAdapter_DetectFiles(t *testing.T) {
	var javaAdapter *EcosystemAdapter
	for _, a := range EcosystemAdapters() {
		if a.Language == "java" {
			a := a
			javaAdapter = &a
			break
		}
	}
	require.NotNil(t, javaAdapter, "Java adapter must be registered")

	// gradle.lockfile must be included so that a project root containing only
	// gradle.lockfile (no build.gradle co-located) is detected as a Java project.
	expected := []string{"pom.xml", "gradle.lockfile", "build.gradle", "build.gradle.kts"}
	assert.Equal(t, expected, javaAdapter.DetectFiles,
		"Java adapter must detect pom.xml, gradle.lockfile, build.gradle, and build.gradle.kts")
}

// TestJavaAdapter_ParseLockfile_PomOnly_ReturnsIncomplete verifies that when
// only pom.xml is present (no gradle.lockfile), ParseLockfile returns
// complete=false. The full Maven transitive closure requires running
// `mvn help:effective-pom` (ACE risk on untrusted repos) — so we degrade to
// incomplete. The caller sets incomplete=true and warns ("unknown ≠ safe").
func TestJavaAdapter_ParseLockfile_PomOnly_ReturnsIncomplete(t *testing.T) {
	dir := t.TempDir()
	// Create a realistic pom.xml so the adapter has a "real" project root.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "pom.xml"), []byte(`<?xml version="1.0"?><project/>`), 0o644))

	var javaAdapter *EcosystemAdapter
	for _, a := range EcosystemAdapters() {
		if a.Language == "java" {
			a := a
			javaAdapter = &a
			break
		}
	}
	require.NotNil(t, javaAdapter, "Java adapter must be registered")
	require.NotNil(t, javaAdapter.ParseLockfile, "Java adapter must provide a ParseLockfile func")

	deps, complete, err := javaAdapter.ParseLockfile(dir)
	assert.NoError(t, err, "pom.xml-only parse must not error (clean degrade)")
	assert.False(t, complete,
		"pom.xml-only → complete=false (transitive closure requires running mvn; ACE risk); "+
			"this is an intentional degrade, not a Phase-0 stub — the real adapter is present "+
			"but cannot produce a complete closure without a gradle.lockfile")
	assert.Nil(t, deps,
		"EcosystemAdapter contract: NEVER return a partial closure with complete=false; "+
			"a partial dep list would produce false NOT_REACHABLE for missing transitives")
}

// TestJavaAdapter_ParseLockfile_NoSubprocess verifies that ParseLockfile does
// not try to spawn a build tool on an empty temp dir. This is the ACE-safety
// check: even without any pom.xml / Gradle files present, the adapter must not
// attempt to run mvn, gradle, or any other executable.
func TestJavaAdapter_ParseLockfile_NoSubprocess(t *testing.T) {
	dir := t.TempDir() // no pom.xml, no Gradle files — intentionally empty

	var javaAdapter *EcosystemAdapter
	for _, a := range EcosystemAdapters() {
		if a.Language == "java" {
			a := a
			javaAdapter = &a
			break
		}
	}
	require.NotNil(t, javaAdapter, "Java adapter must be registered")

	// If ParseLockfile tries to run a subprocess and fails, it would likely return
	// a non-nil error. A pure-Go static parser must succeed (no error) regardless
	// of project content.
	_, complete, err := javaAdapter.ParseLockfile(dir)
	assert.NoError(t, err, "adapter must not spawn a subprocess (ACE-safety)")
	assert.False(t, complete, "empty dir → complete=false (no gradle.lockfile to parse)")
}

// ── detectEcosystems + registry integration ───────────────────────────────────

// TestDetectEcosystems_JavaViaPomXML_RegistryDriven verifies that detectEcosystems
// marks java active when pom.xml is present, and that this detection is driven by
// the Java adapter's DetectFiles (not hardcoded in detectEcosystems).
// This is the integration proof for the table-driven detection refactor.
func TestDetectEcosystems_JavaViaPomXML_RegistryDriven(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "pom.xml"), []byte("{}"), 0o644))

	eco := detectEcosystems(dir)
	assert.True(t, eco.active("java"),
		"pom.xml present → java must be active (registry-driven detection)")
	assert.False(t, eco.active("go"), "no go.mod → Go must not be detected")
}

// TestDetectEcosystems_NoJavaManifests_RegistryDriven verifies that no Java
// manifest → java inactive even after the registry-driven refactor.
func TestDetectEcosystems_NoJavaManifests_RegistryDriven(t *testing.T) {
	dir := t.TempDir()
	// Only a go.mod is present — no Java manifest.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module m"), 0o644))

	eco := detectEcosystems(dir)
	assert.False(t, eco.active("java"),
		"no Java manifest → java must be inactive after registry-driven detection refactor")
	assert.True(t, eco.active("go"), "go.mod present → Go must be detected")
}

// TestDetectEcosystems_PolyglotWithJavaAndGo_RegistryDriven verifies that a
// polyglot repo with both go.mod and pom.xml detects both ecosystems. This is
// the zero-config acceptance test for the registry integration.
func TestDetectEcosystems_PolyglotWithJavaAndGo_RegistryDriven(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module m"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "pom.xml"), []byte("{}"), 0o644))

	eco := detectEcosystems(dir)
	assert.True(t, eco.active("go"), "go.mod → Go detected")
	assert.True(t, eco.active("java"), "pom.xml → Java detected via registry")
}

// ── ResolvedDep ───────────────────────────────────────────────────────────────

// TestResolvedDep_ZeroValue verifies that the zero value of ResolvedDep is safe
// (no required fields panic on use). The gate treats empty DepType as runtime.
func TestResolvedDep_ZeroValue(t *testing.T) {
	var d ResolvedDep
	assert.Equal(t, "", d.Name, "zero Name is empty string")
	assert.Equal(t, "", d.Version, "zero Version is empty string")
	assert.Equal(t, "", d.DepType,
		"zero DepType is empty string (gate treats this as runtime — conservative)")
}

// ── mergeDepType ─────────────────────────────────────────────────────────────

// TestMergeDepType_EmptyDepType_TreatedAsRuntime is the key invariant:
// an empty dep-type MUST be promoted to "runtime" before comparison.
// Failing to do so allows a prior "dev" entry to survive, suppressing a
// runtime-reachable vulnerability through the dev_only gate (false-clean pass).
func TestMergeDepType_EmptyDepType_TreatedAsRuntime(t *testing.T) {
	m := map[string]string{"VULN-1": "dev"} // advisory already tagged dev
	mergeDepType(m, "VULN-1", "")           // empty dep-type = unknown
	assert.Equal(t, "runtime", m["VULN-1"],
		"empty dep-type must promote to runtime (unknown dep-type ≠ safe; "+
			"must not leave advisory tagged dev when an unknown-type dep matches it)")
}

// TestMergeDepType_RuntimeWinsOverDev verifies that "runtime" overwrites an
// existing "dev" entry. The same advisory matched by a dev dep and then a
// runtime dep must end up tagged runtime.
func TestMergeDepType_RuntimeWinsOverDev(t *testing.T) {
	m := map[string]string{"VULN-1": "dev"}
	mergeDepType(m, "VULN-1", "runtime")
	assert.Equal(t, "runtime", m["VULN-1"],
		"runtime dep-type must overwrite existing dev entry")
}

// TestMergeDepType_RuntimeWinsOverTest verifies that "runtime" overwrites
// an existing "test" entry (same as dev).
func TestMergeDepType_RuntimeWinsOverTest(t *testing.T) {
	m := map[string]string{"VULN-1": "test"}
	mergeDepType(m, "VULN-1", "runtime")
	assert.Equal(t, "runtime", m["VULN-1"],
		"runtime dep-type must overwrite existing test entry")
}

// TestMergeDepType_RuntimeNotDowngradedByDev verifies that once an advisory
// is tagged "runtime", a subsequent "dev" dep cannot downgrade it.
func TestMergeDepType_RuntimeNotDowngradedByDev(t *testing.T) {
	m := map[string]string{"VULN-1": "runtime"}
	mergeDepType(m, "VULN-1", "dev")
	assert.Equal(t, "runtime", m["VULN-1"],
		"runtime must not be downgraded to dev")
}

// TestMergeDepType_RuntimeNotDowngradedByEmpty verifies that once an advisory
// is tagged "runtime", a subsequent empty dep-type cannot downgrade it.
// (An empty dep would also become "runtime", so this is a no-op — but the
// map must remain "runtime" regardless.)
func TestMergeDepType_RuntimeNotDowngradedByEmpty(t *testing.T) {
	m := map[string]string{"VULN-1": "runtime"}
	mergeDepType(m, "VULN-1", "")
	assert.Equal(t, "runtime", m["VULN-1"],
		"runtime must not be changed by an empty dep-type")
}

// TestMergeDepType_DevStoredOnFirstSeen verifies that "dev" is stored when
// the advisory has no prior entry.
func TestMergeDepType_DevStoredOnFirstSeen(t *testing.T) {
	m := map[string]string{}
	mergeDepType(m, "VULN-1", "dev")
	assert.Equal(t, "dev", m["VULN-1"],
		"dev dep-type must be stored when advisory has no prior entry")
}

// TestMergeDepType_TestStoredOnFirstSeen verifies that "test" is stored when
// the advisory has no prior entry.
func TestMergeDepType_TestStoredOnFirstSeen(t *testing.T) {
	m := map[string]string{}
	mergeDepType(m, "VULN-1", "test")
	assert.Equal(t, "test", m["VULN-1"],
		"test dep-type must be stored when advisory has no prior entry")
}

// TestMergeDepType_FirstNonRuntimeNotOverwrittenByLaterNonRuntime verifies
// that a second non-runtime dep type does not overwrite the first.
func TestMergeDepType_FirstNonRuntimeNotOverwrittenByLaterNonRuntime(t *testing.T) {
	m := map[string]string{}
	mergeDepType(m, "VULN-1", "dev")
	mergeDepType(m, "VULN-1", "test") // should not overwrite "dev"
	assert.Equal(t, "dev", m["VULN-1"],
		"a second non-runtime dep-type must not overwrite the first non-runtime entry")
}

// TestMergeDepType_MultipleAdvisories verifies that mergeDepType maintains
// independent state per advisory ID (no cross-contamination).
func TestMergeDepType_MultipleAdvisories(t *testing.T) {
	m := map[string]string{}
	mergeDepType(m, "VULN-A", "dev")
	mergeDepType(m, "VULN-B", "runtime")
	mergeDepType(m, "VULN-C", "")
	assert.Equal(t, "dev", m["VULN-A"], "VULN-A must be dev")
	assert.Equal(t, "runtime", m["VULN-B"], "VULN-B must be runtime")
	assert.Equal(t, "runtime", m["VULN-C"],
		"VULN-C must be runtime (empty dep-type promoted)")
}

// ── NormalizeName ─────────────────────────────────────────────────────────────

// TestEcosystemAdapter_NormalizeName_NilIsIdentity verifies that when NormalizeName
// is nil, the adapter does not transform the package name. Maven coordinates
// are case-sensitive; lowercasing an artifactId would miss OSV records.
func TestEcosystemAdapter_NormalizeName_NilIsIdentity(t *testing.T) {
	withCleanRegistry(t, func() {
		RegisterEcosystemAdapter(EcosystemAdapter{
			Ecosystem:     "Maven",
			Language:      "java",
			DetectFiles:   []string{"pom.xml"},
			ParseLockfile: func(_ string) ([]ResolvedDep, bool, error) { return nil, true, nil },
			NormalizeName: nil, // explicitly nil
		})
		adapters := EcosystemAdapters()
		require.Len(t, adapters, 1)
		assert.Nil(t, adapters[0].NormalizeName,
			"nil NormalizeName means identity; caller must use dep.Name as-is for Maven")
	})
}

// TestEcosystemAdapter_NormalizeName_FuncIsCalledWithDepName verifies that a
// non-nil NormalizeName function is stored and can be invoked. This proves
// the field is wired correctly for future adapters (e.g. PyPI).
func TestEcosystemAdapter_NormalizeName_FuncIsCalledWithDepName(t *testing.T) {
	withCleanRegistry(t, func() {
		var calledWith string
		RegisterEcosystemAdapter(EcosystemAdapter{
			Ecosystem:   "Maven",
			Language:    "java",
			DetectFiles: []string{"pom.xml"},
			ParseLockfile: func(_ string) ([]ResolvedDep, bool, error) {
				return nil, true, nil
			},
			NormalizeName: func(name string) string {
				calledWith = name
				return "normalized:" + name
			},
		})
		adapters := EcosystemAdapters()
		require.Len(t, adapters, 1)
		require.NotNil(t, adapters[0].NormalizeName)
		result := adapters[0].NormalizeName("Com.Example:MyLib")
		assert.Equal(t, "normalized:Com.Example:MyLib", result)
		assert.Equal(t, "Com.Example:MyLib", calledWith,
			"NormalizeName must be called with the exact name from the lockfile")
	})
}

// ── registration guards ───────────────────────────────────────────────────────

// TestRegisterEcosystemAdapter_ValidRegistration verifies that a well-formed
// adapter (known language, lockfile parser with a package ceiling) registers
// without panicking.
func TestRegisterEcosystemAdapter_ValidRegistration(t *testing.T) {
	withCleanRegistry(t, func() {
		assert.NotPanics(t, func() {
			RegisterEcosystemAdapter(EcosystemAdapter{
				Ecosystem:     "NuGet",
				Language:      "dotnet",
				DetectFiles:   []string{"*.csproj"},
				MaxConfidence: ceilingPackage,
				ParseLockfile: func(_ string) ([]ResolvedDep, bool, error) { return nil, true, nil },
			})
		})
	})
}

// TestRegisterEcosystemAdapter_PanicsOnUnknownLanguage: a Language missing from
// orderedLanguages would be detectable via DetectFiles but invisible to
// warnUnsupportedEcosystems (which iterates orderedLanguages only), so a
// project using it could scan nothing and still exit 0. Registration must fail
// loudly at init time instead of shipping that silent false-clean.
func TestRegisterEcosystemAdapter_PanicsOnUnknownLanguage(t *testing.T) {
	withCleanRegistry(t, func() {
		assert.PanicsWithValue(t,
			`RegisterEcosystemAdapter: language "nuget" is not listed in orderedLanguages; `+
				`a detected-but-unlisted ecosystem would be skipped without a warning `+
				`and produce a false-clean scan — add it to orderedLanguages first`,
			func() {
				RegisterEcosystemAdapter(EcosystemAdapter{
					Ecosystem:     "NuGet",
					Language:      "nuget", // not an orderedLanguages value
					DetectFiles:   []string{"*.csproj"},
					MaxConfidence: ceilingPackage,
					ParseLockfile: func(_ string) ([]ResolvedDep, bool, error) { return nil, true, nil },
				})
			})
	})
}

// TestRegisterEcosystemAdapter_PanicsOnLockfileSymbolCeiling: lockfile parsing
// can only establish package presence, never a call-graph proof. An adapter
// with ParseLockfile set must not be able to stamp SYMBOL_REACHABLE onto
// findings by declaring a symbol ceiling.
func TestRegisterEcosystemAdapter_PanicsOnLockfileSymbolCeiling(t *testing.T) {
	withCleanRegistry(t, func() {
		assert.PanicsWithValue(t,
			`RegisterEcosystemAdapter: lockfile-static adapter "dotnet" must declare `+
				`ceilingPackage; lockfile parsing cannot prove symbol-level reachability`,
			func() {
				RegisterEcosystemAdapter(EcosystemAdapter{
					Ecosystem:     "NuGet",
					Language:      "dotnet",
					DetectFiles:   []string{"*.csproj"},
					MaxConfidence: ceilingSymbol,
					ParseLockfile: func(_ string) ([]ResolvedDep, bool, error) { return nil, true, nil },
				})
			})
	})
}

// TestRegisterEcosystemAdapter_GraduatedAdapterValid: a graduated (HasPlugin)
// adapter that keeps its ParseLockfile and a package ceiling is well-formed —
// the plugin adds NOT_REACHABLE below the package tier, never SYMBOL above it,
// so ceilingPackage is preserved and registration must not panic.
func TestRegisterEcosystemAdapter_GraduatedAdapterValid(t *testing.T) {
	withCleanRegistry(t, func() {
		assert.NotPanics(t, func() {
			RegisterEcosystemAdapter(EcosystemAdapter{
				Ecosystem:     "NuGet",
				Language:      "dotnet",
				DetectFiles:   []string{"*.csproj"},
				MaxConfidence: ceilingPackage,
				ParseLockfile: func(_ string) ([]ResolvedDep, bool, error) { return nil, true, nil },
				HasPlugin:     true,
				PluginName:    "nuget",
			})
		})
	})
}

// TestRegisterEcosystemAdapter_PanicsOnGraduatedWithoutParser: a graduated
// adapter is still lockfile-backed — the host parses the lockfile as the
// authoritative closure and hands it to the plugin via resolved_deps. A nil
// ParseLockfile would send the plugin an empty closure, risking a false
// NOT_REACHABLE, so registration must fail loudly.
func TestRegisterEcosystemAdapter_PanicsOnGraduatedWithoutParser(t *testing.T) {
	withCleanRegistry(t, func() {
		assert.PanicsWithValue(t,
			`RegisterEcosystemAdapter: graduated adapter "dotnet" (HasPlugin) must keep `+
				`its ParseLockfile as the closure source the plugin consumes; a nil `+
				`parser would send the plugin an empty closure and risk a false NOT_REACHABLE`,
			func() {
				RegisterEcosystemAdapter(EcosystemAdapter{
					Ecosystem:     "NuGet",
					Language:      "dotnet",
					DetectFiles:   []string{"*.csproj"},
					MaxConfidence: ceilingPackage,
					ParseLockfile: nil, // graduated but no closure source
					HasPlugin:     true,
				})
			})
	})
}

// TestRegisterEcosystemAdapter_PanicsOnGraduatedSymbolCeiling: even a graduated
// adapter must keep ceilingPackage — the ceilingPackage guard applies to every
// ParseLockfile-backed adapter regardless of HasPlugin.
func TestRegisterEcosystemAdapter_PanicsOnGraduatedSymbolCeiling(t *testing.T) {
	withCleanRegistry(t, func() {
		assert.PanicsWithValue(t,
			`RegisterEcosystemAdapter: lockfile-static adapter "dotnet" must declare `+
				`ceilingPackage; lockfile parsing cannot prove symbol-level reachability`,
			func() {
				RegisterEcosystemAdapter(EcosystemAdapter{
					Ecosystem:     "NuGet",
					Language:      "dotnet",
					DetectFiles:   []string{"*.csproj"},
					MaxConfidence: ceilingSymbol,
					ParseLockfile: func(_ string) ([]ResolvedDep, bool, error) { return nil, true, nil },
					HasPlugin:     true,
					PluginName:    "nuget",
				})
			})
	})
}

// TestEcosystemAdapter_PluginBaseName verifies the plugin base name resolution:
// PluginName when set, else Language.
func TestEcosystemAdapter_PluginBaseName(t *testing.T) {
	assert.Equal(t, "pub", EcosystemAdapter{Language: "dart", PluginName: "pub"}.pluginBaseName(),
		"PluginName must win over Language when set")
	assert.Equal(t, "java", EcosystemAdapter{Language: "java"}.pluginBaseName(),
		"empty PluginName must default to Language")
}
