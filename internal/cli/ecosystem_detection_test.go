package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commit0v1 "github.com/commit0-dev/commit0-analyzer/pkg/contract/commit0v1"
)

// writeFixtureFile creates a file at dir/name with minimal valid content.
func writeFixtureFile(t *testing.T, dir, name string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte("{}"), 0o644))
}

// ── detectEcosystems ──────────────────────────────────────────────────────────

// TestDetectEcosystems_GoModOnly verifies that a directory containing only
// go.mod selects the Go ecosystem exclusively.
func TestDetectEcosystems_GoModOnly(t *testing.T) {
	dir := t.TempDir()
	writeFixtureFile(t, dir, "go.mod")

	eco := detectEcosystems(dir)
	assert.True(t, eco.active("go"), "go.mod present → Go ecosystem selected")
	assert.False(t, eco.active("js"), "no package.json → JS ecosystem not selected")
	assert.False(t, eco.active("rust"), "no Cargo.toml → Rust ecosystem not selected")
	assert.False(t, eco.active("python"), "no pyproject.toml/requirements.txt → Python not selected")
	assert.False(t, eco.active("java"), "no pom.xml/build.gradle → Java not selected")
}

// TestDetectEcosystems_PackageJSONOnly verifies that a directory containing
// only package.json selects the JS ecosystem exclusively.
func TestDetectEcosystems_PackageJSONOnly(t *testing.T) {
	dir := t.TempDir()
	writeFixtureFile(t, dir, "package.json")

	eco := detectEcosystems(dir)
	assert.False(t, eco.active("go"), "no go.mod → Go ecosystem not selected")
	assert.True(t, eco.active("js"), "package.json present → JS ecosystem selected")
	assert.False(t, eco.active("rust"), "no Cargo.toml → Rust ecosystem not selected")
	assert.False(t, eco.active("python"), "no pyproject.toml/requirements.txt → Python not selected")
	assert.False(t, eco.active("java"), "no pom.xml/build.gradle → Java not selected")
}

// TestDetectEcosystems_BothFiles verifies that a polyglot repo with both
// go.mod and package.json selects both ecosystems.
func TestDetectEcosystems_BothFiles(t *testing.T) {
	dir := t.TempDir()
	writeFixtureFile(t, dir, "go.mod")
	writeFixtureFile(t, dir, "package.json")

	eco := detectEcosystems(dir)
	assert.True(t, eco.active("go"), "go.mod present → Go ecosystem selected")
	assert.True(t, eco.active("js"), "package.json present → JS ecosystem selected")
}

// TestDetectEcosystems_NeitherFile verifies that an empty directory selects
// neither ecosystem.
func TestDetectEcosystems_NeitherFile(t *testing.T) {
	dir := t.TempDir()

	eco := detectEcosystems(dir)
	assert.False(t, eco.active("go"), "no go.mod → Go ecosystem not selected")
	assert.False(t, eco.active("js"), "no package.json → JS ecosystem not selected")
	assert.False(t, eco.active("rust"), "no Cargo.toml → Rust not selected")
	assert.False(t, eco.active("python"), "no pyproject.toml/requirements.txt → Python not selected")
	assert.False(t, eco.active("java"), "no pom.xml/build.gradle → Java not selected")
}

// TestDetectEcosystems_CargoTOMLOnly verifies that Cargo.toml selects the
// Rust ecosystem.
func TestDetectEcosystems_CargoTOMLOnly(t *testing.T) {
	dir := t.TempDir()
	writeFixtureFile(t, dir, "Cargo.toml")

	eco := detectEcosystems(dir)
	assert.True(t, eco.active("rust"), "Cargo.toml present → Rust ecosystem selected")
	assert.False(t, eco.active("go"), "no go.mod → Go not selected")
	assert.False(t, eco.active("js"), "no package.json → JS not selected")
	assert.False(t, eco.active("python"), "no Python manifest → Python not selected")
	assert.False(t, eco.active("java"), "no Java manifest → Java not selected")
}

// TestDetectEcosystems_PyprojectOnly verifies that pyproject.toml selects the
// Python ecosystem.
func TestDetectEcosystems_PyprojectOnly(t *testing.T) {
	dir := t.TempDir()
	writeFixtureFile(t, dir, "pyproject.toml")

	eco := detectEcosystems(dir)
	assert.True(t, eco.active("python"), "pyproject.toml present → Python ecosystem selected")
	assert.False(t, eco.active("go"), "no go.mod → Go not selected")
	assert.False(t, eco.active("js"), "no package.json → JS not selected")
	assert.False(t, eco.active("rust"), "no Cargo.toml → Rust not selected")
	assert.False(t, eco.active("java"), "no Java manifest → Java not selected")
}

// TestDetectEcosystems_RequirementsTxtOnly verifies that requirements.txt
// selects the Python ecosystem.
func TestDetectEcosystems_RequirementsTxtOnly(t *testing.T) {
	dir := t.TempDir()
	writeFixtureFile(t, dir, "requirements.txt")

	eco := detectEcosystems(dir)
	assert.True(t, eco.active("python"), "requirements.txt present → Python ecosystem selected")
	assert.False(t, eco.active("go"), "no go.mod → Go not selected")
	assert.False(t, eco.active("js"), "no package.json → JS not selected")
	assert.False(t, eco.active("rust"), "no Cargo.toml → Rust not selected")
	assert.False(t, eco.active("java"), "no Java manifest → Java not selected")
}

// TestDetectEcosystems_PomXMLOnly verifies that pom.xml selects the Java
// ecosystem.
func TestDetectEcosystems_PomXMLOnly(t *testing.T) {
	dir := t.TempDir()
	writeFixtureFile(t, dir, "pom.xml")

	eco := detectEcosystems(dir)
	assert.True(t, eco.active("java"), "pom.xml present → Java ecosystem selected")
	assert.False(t, eco.active("go"), "no go.mod → Go not selected")
	assert.False(t, eco.active("js"), "no package.json → JS not selected")
	assert.False(t, eco.active("rust"), "no Cargo.toml → Rust not selected")
	assert.False(t, eco.active("python"), "no Python manifest → Python not selected")
}

// TestDetectEcosystems_BuildGradle verifies that build.gradle selects the
// Java ecosystem.
func TestDetectEcosystems_BuildGradle(t *testing.T) {
	dir := t.TempDir()
	writeFixtureFile(t, dir, "build.gradle")

	eco := detectEcosystems(dir)
	assert.True(t, eco.active("java"), "build.gradle present → Java ecosystem selected")
}

// TestDetectEcosystems_BuildGradleKts verifies that build.gradle.kts selects
// the Java ecosystem.
func TestDetectEcosystems_BuildGradleKts(t *testing.T) {
	dir := t.TempDir()
	writeFixtureFile(t, dir, "build.gradle.kts")

	eco := detectEcosystems(dir)
	assert.True(t, eco.active("java"), "build.gradle.kts present → Java ecosystem selected")
}

// TestDetectEcosystems_AllFiveEcosystems verifies that a polyglot repo with
// all five manifest files detects all five ecosystems. This is the zero-config
// acceptance test: `commit0-analyzer scan <path>` auto-detects every ecosystem present.
func TestDetectEcosystems_AllFiveEcosystems(t *testing.T) {
	dir := t.TempDir()
	writeFixtureFile(t, dir, "go.mod")
	writeFixtureFile(t, dir, "package.json")
	writeFixtureFile(t, dir, "Cargo.toml")
	writeFixtureFile(t, dir, "pyproject.toml")
	writeFixtureFile(t, dir, "pom.xml")

	eco := detectEcosystems(dir)
	assert.True(t, eco.active("go"), "go.mod → Go")
	assert.True(t, eco.active("js"), "package.json → JS")
	assert.True(t, eco.active("rust"), "Cargo.toml → Rust")
	assert.True(t, eco.active("python"), "pyproject.toml → Python")
	assert.True(t, eco.active("java"), "pom.xml → Java")
}

// ── resolveLanguage ───────────────────────────────────────────────────────────

// TestResolveLanguage_Auto_GoOnly verifies that --language auto on a Go-only
// repo resolves to the Go ecosystem.
func TestResolveLanguage_Auto_GoOnly(t *testing.T) {
	dir := t.TempDir()
	writeFixtureFile(t, dir, "go.mod")

	eco := detectEcosystems(dir)
	resolved, err := resolveLanguage("auto", eco)
	require.NoError(t, err)
	assert.True(t, resolved.active("go"))
	assert.False(t, resolved.active("js"))
	assert.False(t, resolved.active("rust"))
	assert.False(t, resolved.active("python"))
	assert.False(t, resolved.active("java"))
}

// TestResolveLanguage_Auto_JSOnly verifies that --language auto on a JS-only
// repo resolves to the JS ecosystem.
func TestResolveLanguage_Auto_JSOnly(t *testing.T) {
	dir := t.TempDir()
	writeFixtureFile(t, dir, "package.json")

	eco := detectEcosystems(dir)
	resolved, err := resolveLanguage("auto", eco)
	require.NoError(t, err)
	assert.False(t, resolved.active("go"))
	assert.True(t, resolved.active("js"))
}

// TestResolveLanguage_Auto_Both verifies that --language auto on a polyglot
// repo resolves to both ecosystems.
func TestResolveLanguage_Auto_Both(t *testing.T) {
	dir := t.TempDir()
	writeFixtureFile(t, dir, "go.mod")
	writeFixtureFile(t, dir, "package.json")

	eco := detectEcosystems(dir)
	resolved, err := resolveLanguage("auto", eco)
	require.NoError(t, err)
	assert.True(t, resolved.active("go"))
	assert.True(t, resolved.active("js"))
}

// TestResolveLanguage_Auto_AllFive verifies that --language auto (the default)
// on a polyglot repo with all five manifest files resolves to all five
// ecosystems. This proves the zero-config UX invariant: a single `commit0-analyzer scan
// <path>` runs every detected plugin without any --language flag.
func TestResolveLanguage_Auto_AllFive(t *testing.T) {
	dir := t.TempDir()
	writeFixtureFile(t, dir, "go.mod")
	writeFixtureFile(t, dir, "package.json")
	writeFixtureFile(t, dir, "Cargo.toml")
	writeFixtureFile(t, dir, "pyproject.toml")
	writeFixtureFile(t, dir, "pom.xml")

	eco := detectEcosystems(dir)
	resolved, err := resolveLanguage("auto", eco)
	require.NoError(t, err)
	assert.True(t, resolved.active("go"), "auto must include Go")
	assert.True(t, resolved.active("js"), "auto must include JS")
	assert.True(t, resolved.active("rust"), "auto must include Rust")
	assert.True(t, resolved.active("python"), "auto must include Python")
	assert.True(t, resolved.active("java"), "auto must include Java")
}

// TestResolveLanguage_GoOverride forces Go even when package.json is present.
func TestResolveLanguage_GoOverride(t *testing.T) {
	dir := t.TempDir()
	writeFixtureFile(t, dir, "go.mod")
	writeFixtureFile(t, dir, "package.json")

	eco := detectEcosystems(dir)
	resolved, err := resolveLanguage("go", eco)
	require.NoError(t, err)
	assert.True(t, resolved.active("go"))
	assert.False(t, resolved.active("js"))
	assert.False(t, resolved.active("rust"))
	assert.False(t, resolved.active("python"))
	assert.False(t, resolved.active("java"))
}

// TestResolveLanguage_JSOverride forces JS even when go.mod is present.
func TestResolveLanguage_JSOverride(t *testing.T) {
	dir := t.TempDir()
	writeFixtureFile(t, dir, "go.mod")
	writeFixtureFile(t, dir, "package.json")

	eco := detectEcosystems(dir)
	resolved, err := resolveLanguage("js", eco)
	require.NoError(t, err)
	assert.False(t, resolved.active("go"))
	assert.True(t, resolved.active("js"))
	assert.False(t, resolved.active("rust"))
	assert.False(t, resolved.active("python"))
	assert.False(t, resolved.active("java"))
}

// TestResolveLanguage_RustOverride forces Rust even when other manifests are
// present.
func TestResolveLanguage_RustOverride(t *testing.T) {
	dir := t.TempDir()
	writeFixtureFile(t, dir, "go.mod")
	writeFixtureFile(t, dir, "package.json")
	writeFixtureFile(t, dir, "Cargo.toml")

	eco := detectEcosystems(dir)
	resolved, err := resolveLanguage("rust", eco)
	require.NoError(t, err)
	assert.False(t, resolved.active("go"))
	assert.False(t, resolved.active("js"))
	assert.True(t, resolved.active("rust"))
	assert.False(t, resolved.active("python"))
	assert.False(t, resolved.active("java"))
}

// TestResolveLanguage_PythonOverride forces Python even when other manifests
// are present.
func TestResolveLanguage_PythonOverride(t *testing.T) {
	dir := t.TempDir()
	writeFixtureFile(t, dir, "go.mod")
	writeFixtureFile(t, dir, "pyproject.toml")

	eco := detectEcosystems(dir)
	resolved, err := resolveLanguage("python", eco)
	require.NoError(t, err)
	assert.False(t, resolved.active("go"))
	assert.False(t, resolved.active("js"))
	assert.False(t, resolved.active("rust"))
	assert.True(t, resolved.active("python"))
	assert.False(t, resolved.active("java"))
}

// TestResolveLanguage_JavaOverride forces Java even when other manifests are
// present.
func TestResolveLanguage_JavaOverride(t *testing.T) {
	dir := t.TempDir()
	writeFixtureFile(t, dir, "go.mod")
	writeFixtureFile(t, dir, "pom.xml")

	eco := detectEcosystems(dir)
	resolved, err := resolveLanguage("java", eco)
	require.NoError(t, err)
	assert.False(t, resolved.active("go"))
	assert.False(t, resolved.active("js"))
	assert.False(t, resolved.active("rust"))
	assert.False(t, resolved.active("python"))
	assert.True(t, resolved.active("java"))
}

// TestResolveLanguage_UnknownValue verifies that an unrecognised --language
// value returns an operational error rather than silently falling through.
func TestResolveLanguage_UnknownValue(t *testing.T) {
	eco := ecosystems{"go": true, "js": true}
	_, err := resolveLanguage("bogus", eco)
	require.Error(t, err, "--language bogus must return an error")
	assert.Contains(t, err.Error(), "bogus", "error message must name the invalid value")
	assert.Contains(t, err.Error(), "auto|go|js|rust|python|java", "error message must list valid values")
}

// ── warnUnsupportedEcosystems ─────────────────────────────────────────────────
//
// These tests verify the "unknown ≠ safe" invariant for ecosystems that are
// detected (or explicitly selected via --language) but have no scan path yet
// (rust, python, java). A detected-but-unscannable ecosystem MUST set
// incomplete=true and warn to stderr — never silently exit 0 (false-clean).

// TestWarnUnsupportedEcosystems_NonePresent verifies that when only Go and JS
// ecosystems are in scope, no warning is emitted and incomplete stays false.
func TestWarnUnsupportedEcosystems_NonePresent(t *testing.T) {
	var buf bytes.Buffer
	eco := ecosystems{"go": true, "js": true}
	gotIncomplete := warnUnsupportedEcosystems(eco, &buf)
	assert.False(t, gotIncomplete, "Go+JS in scope → no incomplete signal")
	assert.Empty(t, buf.String(), "no warning when no unsupported ecosystem is present")
}

// TestWarnUnsupportedEcosystems_RustOnly verifies that a Rust-only ecosystem
// set (e.g. --language rust) emits a warning and returns incomplete=true.
// This is the critical "unknown ≠ safe" regression: prior code exited 0 clean.
func TestWarnUnsupportedEcosystems_RustOnly(t *testing.T) {
	var buf bytes.Buffer
	eco := ecosystems{"rust": true}
	gotIncomplete := warnUnsupportedEcosystems(eco, &buf)
	assert.True(t, gotIncomplete, "Rust detected but no scan path → incomplete must be true")
	assert.Contains(t, buf.String(), "rust", "warning must name the unsupported ecosystem")
	assert.Contains(t, buf.String(), "incomplete", "warning must mention incomplete signal")
}

// TestWarnUnsupportedEcosystems_PythonOnly verifies that a Python-only
// ecosystem set emits a warning and returns incomplete=true.
func TestWarnUnsupportedEcosystems_PythonOnly(t *testing.T) {
	var buf bytes.Buffer
	eco := ecosystems{"python": true}
	gotIncomplete := warnUnsupportedEcosystems(eco, &buf)
	assert.True(t, gotIncomplete, "Python detected but no scan path → incomplete must be true")
	assert.Contains(t, buf.String(), "python", "warning must name the unsupported ecosystem")
	assert.Contains(t, buf.String(), "incomplete", "warning must mention incomplete signal")
}

// TestWarnUnsupportedEcosystems_JavaOnly verifies that a Java-only ecosystem
// set emits a warning and returns incomplete=true.
func TestWarnUnsupportedEcosystems_JavaOnly(t *testing.T) {
	var buf bytes.Buffer
	eco := ecosystems{"java": true}
	gotIncomplete := warnUnsupportedEcosystems(eco, &buf)
	assert.True(t, gotIncomplete, "Java detected but no scan path → incomplete must be true")
	assert.Contains(t, buf.String(), "java", "warning must name the unsupported ecosystem")
	assert.Contains(t, buf.String(), "incomplete", "warning must mention incomplete signal")
}

// TestWarnUnsupportedEcosystems_AllThreeUnsupported verifies that when rust,
// python, and java are all in scope (e.g. auto on a polyglot repo without Go
// or JS), all three are warned and incomplete is true.
func TestWarnUnsupportedEcosystems_AllThreeUnsupported(t *testing.T) {
	var buf bytes.Buffer
	eco := ecosystems{"rust": true, "python": true, "java": true}
	gotIncomplete := warnUnsupportedEcosystems(eco, &buf)
	assert.True(t, gotIncomplete, "rust+python+java detected → incomplete must be true")
	output := buf.String()
	assert.Contains(t, output, "rust", "warning must name rust")
	assert.Contains(t, output, "python", "warning must name python")
	assert.Contains(t, output, "java", "warning must name java")
	assert.Contains(t, output, "incomplete", "warning must mention incomplete signal")
}

// TestWarnUnsupportedEcosystems_PolyglotWithGoAndRust verifies the partial
// coverage gap: a polyglot repo with go.mod + Cargo.toml runs Go (fully) but
// Rust has no scan path → incomplete=true and warning emitted. This is the
// "silent coverage gap under zero-config auto" case from the blocking findings.
func TestWarnUnsupportedEcosystems_PolyglotWithGoAndRust(t *testing.T) {
	var buf bytes.Buffer
	eco := ecosystems{"go": true, "rust": true}
	gotIncomplete := warnUnsupportedEcosystems(eco, &buf)
	assert.True(t, gotIncomplete, "Go+Rust: Rust has no scan path → incomplete must be true")
	output := buf.String()
	assert.Contains(t, output, "rust", "warning must name the unsupported ecosystem")
	assert.NotContains(t, output, "go", "Go is supported; its name must not appear in the warning")
}

// TestWarnUnsupportedEcosystems_GoOnly verifies that a Go-only ecosystem
// produces no warning and no incomplete signal (Go has a full scan path).
func TestWarnUnsupportedEcosystems_GoOnly(t *testing.T) {
	var buf bytes.Buffer
	eco := ecosystems{"go": true}
	gotIncomplete := warnUnsupportedEcosystems(eco, &buf)
	assert.False(t, gotIncomplete, "Go-only → fully supported, no incomplete")
	assert.Empty(t, buf.String(), "no warning for fully-supported ecosystem")
}

// TestWarnUnsupportedEcosystems_JSOnly verifies that a JS-only ecosystem
// produces no warning and no incomplete signal (JS has a full scan path).
func TestWarnUnsupportedEcosystems_JSOnly(t *testing.T) {
	var buf bytes.Buffer
	eco := ecosystems{"js": true}
	gotIncomplete := warnUnsupportedEcosystems(eco, &buf)
	assert.False(t, gotIncomplete, "JS-only → fully supported, no incomplete")
	assert.Empty(t, buf.String(), "no warning for fully-supported ecosystem")
}

// ── hasPartialityMarker (wire-level incomplete signal) ────────────────────────
//
// These tests verify the ecosystem-agnostic wire contract for plugin-signalled
// partiality. A plugin that detects its own analysis gap (partial resolve,
// no-venv, missing environment, dynamic dispatch, etc.) MUST emit a Finding
// with Confidence=UNKNOWN and Properties["synthetic"]="true". The host reads
// this marker and sets incomplete=true at the policy gate.
//
// This generalises the JS modelIncomplete→incomplete path so every new ecosystem
// plugin can reuse the same contract without per-language host wiring.

// TestHasPartialityMarker_EmptySlice verifies that no findings → no marker.
func TestHasPartialityMarker_EmptySlice(t *testing.T) {
	assert.False(t, hasPartialityMarker(nil), "nil slice → no partiality marker")
	assert.False(t, hasPartialityMarker([]*commit0v1.Finding{}), "empty slice → no partiality marker")
}

// TestHasPartialityMarker_NoSyntheticFindings verifies that normal reachable
// findings without the synthetic marker do not trigger the signal.
func TestHasPartialityMarker_NoSyntheticFindings(t *testing.T) {
	findings := []*commit0v1.Finding{
		{
			Confidence: commit0v1.Confidence_CONFIDENCE_PACKAGE_REACHABLE,
			Properties: map[string]string{"sources": "osv.dev"},
		},
		{
			Confidence: commit0v1.Confidence_CONFIDENCE_SYMBOL_REACHABLE,
		},
		{
			Confidence: commit0v1.Confidence_CONFIDENCE_NOT_REACHABLE,
		},
	}
	assert.False(t, hasPartialityMarker(findings),
		"reachable/not-reachable findings without synthetic marker → no partiality signal")
}

// TestHasPartialityMarker_UnknownWithoutSyntheticKey verifies that a
// CONFIDENCE_UNKNOWN finding WITHOUT the "synthetic"="true" property does NOT
// trigger the incomplete signal. Only the explicit marker counts.
func TestHasPartialityMarker_UnknownWithoutSyntheticKey(t *testing.T) {
	findings := []*commit0v1.Finding{
		{
			Confidence: commit0v1.Confidence_CONFIDENCE_UNKNOWN,
			Properties: map[string]string{"reason": "dynamic dispatch"},
		},
	}
	assert.False(t, hasPartialityMarker(findings),
		"CONFIDENCE_UNKNOWN without synthetic=true key → no partiality signal")
}

// TestHasPartialityMarker_UnknownWithSyntheticTrue is the positive case:
// a stub plugin emitting a CONFIDENCE_UNKNOWN finding with Properties["synthetic"]="true"
// MUST flip the incomplete signal. This is the core wire-contract acceptance test.
func TestHasPartialityMarker_UnknownWithSyntheticTrue(t *testing.T) {
	// This is the shape a plugin emits to signal partial analysis (e.g. Rust
	// plugin detected partial Cargo.lock resolve, Python plugin detected no-venv).
	// The host must translate this into incomplete=true at the policy gate.
	partialFinding := &commit0v1.Finding{
		Confidence: commit0v1.Confidence_CONFIDENCE_UNKNOWN,
		Properties: map[string]string{
			"synthetic": "true",
			"cause":     "partial Cargo.lock resolution: 3 crates unresolved",
		},
	}
	findings := []*commit0v1.Finding{partialFinding}
	assert.True(t, hasPartialityMarker(findings),
		"CONFIDENCE_UNKNOWN + Properties[synthetic]=true → partiality marker MUST be detected")
}

// TestHasPartialityMarker_MixedFindingsWithMarker verifies that a single
// synthetic marker in a mixed slice of findings is enough to trigger incomplete.
// Plugins emit real findings for resolved deps and one synthetic UNKNOWN per
// unresolvable dep; the host must flag incomplete even if most deps resolved.
func TestHasPartialityMarker_MixedFindingsWithMarker(t *testing.T) {
	findings := []*commit0v1.Finding{
		{
			// Normal reachable finding for a resolved dep.
			Confidence: commit0v1.Confidence_CONFIDENCE_PACKAGE_REACHABLE,
			Properties: map[string]string{"sources": "osv.dev"},
		},
		{
			// Synthetic UNKNOWN for a dep the plugin could not resolve.
			Confidence: commit0v1.Confidence_CONFIDENCE_UNKNOWN,
			Properties: map[string]string{
				"synthetic": "true",
				"cause":     "crate serde: cfg feature resolution incomplete",
			},
		},
	}
	assert.True(t, hasPartialityMarker(findings),
		"one synthetic marker in a mixed slice → incomplete must be true")
}

// TestHasPartialityMarker_SyntheticKeyWrongValue verifies that
// Properties["synthetic"]="false" (or any value other than "true") does NOT
// trigger the signal. The marker is a boolean-valued property.
func TestHasPartialityMarker_SyntheticKeyWrongValue(t *testing.T) {
	findings := []*commit0v1.Finding{
		{
			Confidence: commit0v1.Confidence_CONFIDENCE_UNKNOWN,
			Properties: map[string]string{"synthetic": "false"},
		},
	}
	assert.False(t, hasPartialityMarker(findings),
		`Properties["synthetic"]="false" must not trigger the incomplete signal`)
}

// TestHasPartialityMarker_NilProperties verifies that a CONFIDENCE_UNKNOWN
// finding with nil Properties (common zero-value case) is handled safely.
func TestHasPartialityMarker_NilProperties(t *testing.T) {
	findings := []*commit0v1.Finding{
		{
			Confidence: commit0v1.Confidence_CONFIDENCE_UNKNOWN,
			// Properties is nil (zero value) — must not panic.
		},
	}
	assert.False(t, hasPartialityMarker(findings),
		"CONFIDENCE_UNKNOWN with nil Properties must not panic and must return false")
}
