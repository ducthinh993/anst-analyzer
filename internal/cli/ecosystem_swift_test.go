package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/commit0-dev/commit0-analyzer/internal/advisory"
)

// ── adapter registration ──────────────────────────────────────────────────────

// TestSwiftAdapterRegistered verifies that the SwiftURL Lane-A adapter is
// registered in the global registry with the expected metadata.
func TestSwiftAdapterRegistered(t *testing.T) {
	var found *EcosystemAdapter
	for _, a := range EcosystemAdapters() {
		if a.Language == "swift" {
			a := a
			found = &a
			break
		}
	}
	require.NotNil(t, found, "SwiftURL adapter with Language=swift must be registered")
	assert.Equal(t, advisory.EcosystemSwiftURL, found.Ecosystem, "Ecosystem must be 'SwiftURL'")
	assert.Nil(t, found.NormalizeName, "NormalizeName must be nil (normalization applied inside ParseLockfile)")
	assert.Contains(t, found.DetectFiles, "Package.resolved", "Package.resolved must be in DetectFiles")
}

// ── detectEcosystems integration ─────────────────────────────────────────────

// TestDetectEcosystems_PackageResolved verifies that Package.resolved triggers
// Swift ecosystem detection via the registry-driven path.
func TestDetectEcosystems_PackageResolved(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Package.resolved"),
		[]byte(packageResolvedV2NIO), 0o644))

	eco := detectEcosystems(dir)
	assert.True(t, eco.active("swift"), "Package.resolved present → Swift ecosystem detected")
	assert.False(t, eco.active("go"), "no go.mod → Go not detected")
	assert.False(t, eco.active("ruby"), "no Gemfile → Ruby not detected")
}

// TestDetectEcosystems_NoPackageResolved verifies that a directory without
// Package.resolved does not set hasSwift.
func TestDetectEcosystems_NoPackageResolved(t *testing.T) {
	dir := t.TempDir()
	// Write Package.swift (executable; must never trigger detection alone).
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Package.swift"),
		[]byte("// swift-tools-version:5.9\n"), 0o644))

	eco := detectEcosystems(dir)
	assert.False(t, eco.active("swift"),
		"Package.swift alone must not set hasSwift (only Package.resolved is safe to parse)")
}

// ── normalizeSwiftURL ──────────────────────────────────────────────────────────

// TestNormalizeSwiftURL covers all URL forms that may appear in Package.resolved.
func TestNormalizeSwiftURL(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   string
		want string
	}{
		// Standard HTTPS .git form (most common in Package.resolved).
		{"https://github.com/apple/swift-nio.git", "github.com/apple/swift-nio"},
		// HTTPS without .git suffix.
		{"https://github.com/apple/swift-nio", "github.com/apple/swift-nio"},
		// HTTP (rare but valid).
		{"http://github.com/apple/swift-nio.git", "github.com/apple/swift-nio"},
		// SSH git@ form.
		{"git@github.com:apple/swift-nio.git", "github.com/apple/swift-nio"},
		{"git@github.com:apple/swift-nio", "github.com/apple/swift-nio"},
		// Trailing slash (defensive).
		{"https://github.com/apple/swift-nio.git/", "github.com/apple/swift-nio"},
		// Mixed case (git hosting is case-insensitive; OSV uses lowercase).
		{"https://GitHub.com/Apple/swift-NIO.git", "github.com/apple/swift-nio"},
		// Already normalized (no-op).
		{"github.com/apple/swift-nio", "github.com/apple/swift-nio"},
		// Empty string.
		{"", ""},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			got := normalizeSwiftURL(tc.in)
			assert.Equal(t, tc.want, got, "normalizeSwiftURL(%q)", tc.in)
		})
	}
}

// ── parsePackageResolved — format v2 ──────────────────────────────────────────

// TestParsePackageResolved_V2_Basic verifies that a typical v2 Package.resolved
// with concrete version pins is parsed into a complete closure.
func TestParsePackageResolved_V2_Basic(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Package.resolved"),
		[]byte(packageResolvedV2NIO), 0o644))

	deps, complete, err := parsePackageResolved(dir)
	require.NoError(t, err)
	assert.True(t, complete, "all pins have concrete versions → complete=true")

	byName := make(map[string]ResolvedDep, len(deps))
	for _, d := range deps {
		byName[d.Name] = d
	}

	// URL is normalized: "https://github.com/apple/swift-nio.git" → "github.com/apple/swift-nio"
	require.Contains(t, byName, "github.com/apple/swift-nio")
	assert.Equal(t, "2.41.0", byName["github.com/apple/swift-nio"].Version)
	assert.Equal(t, "runtime", byName["github.com/apple/swift-nio"].DepType,
		"all deps tagged runtime (dep-type not in Package.resolved)")

	require.Contains(t, byName, "github.com/apple/swift-collections")
	assert.Equal(t, "1.0.5", byName["github.com/apple/swift-collections"].Version)
	assert.Equal(t, "runtime", byName["github.com/apple/swift-collections"].DepType)
}

// TestParsePackageResolved_V3_Basic verifies that format v3 (identical structure
// to v2 with a different version field) is parsed the same way as v2.
func TestParsePackageResolved_V3_Basic(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Package.resolved"),
		[]byte(packageResolvedV3Vapor), 0o644))

	deps, complete, err := parsePackageResolved(dir)
	require.NoError(t, err)
	assert.True(t, complete)

	byName := make(map[string]ResolvedDep, len(deps))
	for _, d := range deps {
		byName[d.Name] = d
	}

	require.Contains(t, byName, "github.com/vapor/vapor")
	assert.Equal(t, "4.83.1", byName["github.com/vapor/vapor"].Version)
}

// TestParsePackageResolved_V1_Basic verifies that format v1 (object.pins with
// repositoryURL) is parsed correctly.
func TestParsePackageResolved_V1_Basic(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Package.resolved"),
		[]byte(packageResolvedV1Alamofire), 0o644))

	deps, complete, err := parsePackageResolved(dir)
	require.NoError(t, err)
	assert.True(t, complete)

	byName := make(map[string]ResolvedDep, len(deps))
	for _, d := range deps {
		byName[d.Name] = d
	}

	require.Contains(t, byName, "github.com/alamofire/alamofire")
	assert.Equal(t, "5.7.1", byName["github.com/alamofire/alamofire"].Version)
}

// ── parsePackageResolved — branch / revision pins ─────────────────────────────

// TestParsePackageResolved_BranchPin verifies that a branch-pinned dep (no
// concrete version) makes complete=false and is excluded from the closure.
// The remaining concrete-version pins are still returned (partial closure).
func TestParsePackageResolved_BranchPin(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Package.resolved"),
		[]byte(packageResolvedV2BranchPin), 0o644))

	deps, complete, err := parsePackageResolved(dir)
	require.NoError(t, err)
	assert.False(t, complete,
		"branch pin without version → complete=false (undecidable closure)")

	// The concrete-version pin must still appear.
	byName := make(map[string]string, len(deps))
	for _, d := range deps {
		byName[d.Name] = d.Version
	}
	require.Contains(t, byName, "github.com/apple/swift-nio",
		"concrete-version pin must appear even when another pin is a branch pin")
	assert.NotContains(t, byName, "github.com/some/branch-dep",
		"branch-only pin must be excluded (no decidable version)")
}

// TestParsePackageResolved_RevisionOnlyPin verifies that a revision-only pin
// (no concrete version) makes complete=false.
func TestParsePackageResolved_RevisionOnlyPin(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Package.resolved"),
		[]byte(packageResolvedV2RevisionPin), 0o644))

	deps, complete, err := parsePackageResolved(dir)
	require.NoError(t, err)
	assert.False(t, complete,
		"revision-only pin (no version) → complete=false")

	// The concrete-version pin must still appear.
	byName := make(map[string]string, len(deps))
	for _, d := range deps {
		byName[d.Name] = d.Version
	}
	require.Contains(t, byName, "github.com/apple/swift-nio")
}

// ── parsePackageResolved — edge cases ─────────────────────────────────────────

// TestParsePackageResolved_Absent verifies that a missing Package.resolved
// returns (nil, false, nil) — the caller must mark the scan incomplete.
func TestParsePackageResolved_Absent(t *testing.T) {
	dir := t.TempDir()

	deps, complete, err := parsePackageResolved(dir)
	require.NoError(t, err, "absent Package.resolved must not return an error")
	assert.False(t, complete)
	assert.Nil(t, deps)
}

// TestParsePackageResolved_MalformedJSON verifies that a malformed JSON file
// returns an error and complete=false (not a silent false-clean).
func TestParsePackageResolved_MalformedJSON(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Package.resolved"),
		[]byte("{not valid json"), 0o644))

	deps, complete, err := parsePackageResolved(dir)
	assert.Error(t, err, "malformed JSON must return an error")
	assert.False(t, complete)
	assert.Nil(t, deps)
}

// TestParsePackageResolved_UnknownVersion verifies that an unsupported format
// version returns an error (not a false-clean empty closure).
func TestParsePackageResolved_UnknownVersion(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Package.resolved"),
		[]byte(`{"version": 99, "pins": []}`), 0o644))

	deps, complete, err := parsePackageResolved(dir)
	assert.Error(t, err, "unknown format version must return an error")
	assert.Contains(t, err.Error(), "unsupported Package.resolved format version 99")
	assert.False(t, complete)
	assert.Nil(t, deps)
}

// TestParsePackageResolved_EmptyV2 verifies that a v2 Package.resolved with no
// pins (zero-dependency project) returns complete=true with an empty closure.
func TestParsePackageResolved_EmptyV2(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Package.resolved"),
		[]byte(`{"version": 2, "pins": []}`), 0o644))

	deps, complete, err := parsePackageResolved(dir)
	require.NoError(t, err)
	assert.True(t, complete, "empty pins array → complete=true (zero-dep project)")
	assert.Empty(t, deps)
}

// TestParsePackageResolved_EmptyV1 verifies that a v1 Package.resolved with no
// object (null) returns complete=true with an empty closure.
func TestParsePackageResolved_EmptyV1(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Package.resolved"),
		[]byte(`{"version": 1}`), 0o644))

	deps, complete, err := parsePackageResolved(dir)
	require.NoError(t, err)
	assert.True(t, complete, "v1 without object → complete=true (zero-dep project)")
	assert.Nil(t, deps)
}

// TestParsePackageResolved_AllDepTypesRuntime verifies that all deps from
// Package.resolved are tagged "runtime" regardless of their actual role, because
// dep-type cannot be inferred without evaluating Package.swift (ACE risk).
func TestParsePackageResolved_AllDepTypesRuntime(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Package.resolved"),
		[]byte(packageResolvedV2NIO), 0o644))

	deps, complete, err := parsePackageResolved(dir)
	require.NoError(t, err)
	assert.True(t, complete)

	for _, d := range deps {
		assert.Equal(t, "runtime", d.DepType,
			"dep %q: all Swift deps must be tagged runtime (dep-type unknown without Package.swift)", d.Name)
	}
}

// ── fixtures ──────────────────────────────────────────────────────────────────

// packageResolvedV2NIO is a representative Package.resolved v2 for a project
// using swift-nio and swift-collections. The swift-nio pin is at v2.41.0, which
// falls in the real OSV advisory GHSA-7fj7-39wj-c64f range [2.41.0, 2.42.0).
const packageResolvedV2NIO = `{
  "version": 2,
  "pins": [
    {
      "identity": "swift-nio",
      "kind": "remoteSourceControl",
      "location": "https://github.com/apple/swift-nio.git",
      "state": {
        "revision": "abc123def456789abc123def456789abc123def4",
        "version": "2.41.0"
      }
    },
    {
      "identity": "swift-collections",
      "kind": "remoteSourceControl",
      "location": "https://github.com/apple/swift-collections.git",
      "state": {
        "revision": "def456abc789012def456abc789012def456abc7",
        "version": "1.0.5"
      }
    }
  ]
}`

// packageResolvedV3Vapor is a representative Package.resolved v3 for a Vapor project.
const packageResolvedV3Vapor = `{
  "originHash": "abc123",
  "version": 3,
  "pins": [
    {
      "identity": "vapor",
      "kind": "remoteSourceControl",
      "location": "https://github.com/vapor/vapor.git",
      "state": {
        "revision": "cafe1234",
        "version": "4.83.1"
      }
    }
  ]
}`

// packageResolvedV1Alamofire is a representative Package.resolved v1 (old format).
const packageResolvedV1Alamofire = `{
  "version": 1,
  "object": {
    "pins": [
      {
        "package": "Alamofire",
        "repositoryURL": "https://github.com/Alamofire/Alamofire.git",
        "state": {
          "branch": null,
          "revision": "f455c2975872ccd2d9c81594c658af65716e9b9a",
          "version": "5.7.1"
        }
      }
    ]
  }
}`

// packageResolvedV2BranchPin has one concrete-version pin and one branch-only pin.
// The branch pin makes complete=false; the concrete pin must still appear.
const packageResolvedV2BranchPin = `{
  "version": 2,
  "pins": [
    {
      "identity": "swift-nio",
      "kind": "remoteSourceControl",
      "location": "https://github.com/apple/swift-nio.git",
      "state": {
        "revision": "abc123",
        "version": "2.41.0"
      }
    },
    {
      "identity": "branch-dep",
      "kind": "remoteSourceControl",
      "location": "https://github.com/some/branch-dep.git",
      "state": {
        "branch": "main",
        "revision": "deadbeef"
      }
    }
  ]
}`

// packageResolvedV2RevisionPin has one concrete-version pin and one revision-only pin.
const packageResolvedV2RevisionPin = `{
  "version": 2,
  "pins": [
    {
      "identity": "swift-nio",
      "kind": "remoteSourceControl",
      "location": "https://github.com/apple/swift-nio.git",
      "state": {
        "revision": "abc123",
        "version": "2.41.0"
      }
    },
    {
      "identity": "revision-dep",
      "kind": "remoteSourceControl",
      "location": "https://github.com/some/revision-dep.git",
      "state": {
        "revision": "cafebabe1234567890"
      }
    }
  ]
}`
