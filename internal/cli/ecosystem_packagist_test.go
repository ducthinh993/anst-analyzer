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

// TestPackagistAdapterRegistered verifies that the Packagist lockfile-static adapter is
// registered in the global registry with the expected metadata.
func TestPackagistAdapterRegistered(t *testing.T) {
	var found *EcosystemAdapter
	for _, a := range EcosystemAdapters() {
		if a.Language == "php" {
			a := a
			found = &a
			break
		}
	}
	require.NotNil(t, found, "Packagist adapter with Language=php must be registered")
	assert.Equal(t, advisory.EcosystemPackagist, found.Ecosystem, "Ecosystem must be 'Packagist'")
	assert.Nil(t, found.NormalizeName, "NormalizeName must be nil (Packagist uses lowercase canonical names)")
	assert.Contains(t, found.DetectFiles, "composer.lock")
	assert.Contains(t, found.DetectFiles, "composer.json")
}

// ── detectEcosystems integration ─────────────────────────────────────────────

// TestDetectEcosystems_ComposerLock verifies that composer.lock triggers PHP ecosystem detection.
func TestDetectEcosystems_ComposerLock(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "composer.lock"),
		[]byte(composerLockRuntimeAndDev), 0o644))

	eco := detectEcosystems(dir)
	assert.True(t, eco.active("php"), "composer.lock present → PHP ecosystem detected")
	assert.False(t, eco.active("go"), "no go.mod → Go not detected")
	assert.False(t, eco.active("dotnet"), "no packages.lock.json → .NET not detected")
}

// TestDetectEcosystems_ComposerJSON verifies that composer.json alone triggers
// PHP detection (manifest-only project; scan will be marked incomplete).
func TestDetectEcosystems_ComposerJSON(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "composer.json"),
		[]byte(`{"require": {"monolog/monolog": "^2.0"}}`), 0o644))

	eco := detectEcosystems(dir)
	assert.True(t, eco.active("php"), "composer.json present → PHP ecosystem detected (incomplete scan)")
}

// ── parseComposerLockfile ─────────────────────────────────────────────────────

// TestParseComposerLockfile_RuntimeAndDev verifies that runtime and dev deps are
// parsed with the correct DepType from their respective sections.
func TestParseComposerLockfile_RuntimeAndDev(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "composer.lock"),
		[]byte(composerLockRuntimeAndDev), 0o644))

	deps, complete, err := parseComposerLockfile(dir)
	require.NoError(t, err)
	assert.True(t, complete, "composer.lock present → complete=true")
	require.Len(t, deps, 3)

	// Index is deterministic: packages first, then packages-dev.
	assert.Equal(t, "monolog/monolog", deps[0].Name)
	assert.Equal(t, "2.3.5", deps[0].Version)
	assert.Equal(t, "runtime", deps[0].DepType)

	assert.Equal(t, "symfony/http-foundation", deps[1].Name)
	assert.Equal(t, "5.4.0", deps[1].Version)
	assert.Equal(t, "runtime", deps[1].DepType)

	assert.Equal(t, "phpunit/phpunit", deps[2].Name)
	assert.Equal(t, "9.5.10", deps[2].Version)
	assert.Equal(t, "dev", deps[2].DepType)
}

// TestParseComposerLockfile_RuntimeOnly verifies that a lockfile with no
// packages-dev section is parsed correctly (complete=true, all deps runtime).
func TestParseComposerLockfile_RuntimeOnly(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "composer.lock"),
		[]byte(composerLockRuntimeOnly), 0o644))

	deps, complete, err := parseComposerLockfile(dir)
	require.NoError(t, err)
	assert.True(t, complete)
	require.Len(t, deps, 1)
	assert.Equal(t, "guzzlehttp/guzzle", deps[0].Name)
	assert.Equal(t, "7.4.5", deps[0].Version)
	assert.Equal(t, "runtime", deps[0].DepType)
}

// TestParseComposerLockfile_DevOnly verifies that a lockfile containing only
// dev packages is parsed correctly (complete=true, all deps dev).
func TestParseComposerLockfile_DevOnly(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "composer.lock"),
		[]byte(composerLockDevOnly), 0o644))

	deps, complete, err := parseComposerLockfile(dir)
	require.NoError(t, err)
	assert.True(t, complete)
	require.Len(t, deps, 1)
	assert.Equal(t, "phpunit/phpunit", deps[0].Name)
	assert.Equal(t, "dev", deps[0].DepType)
}

// TestParseComposerLockfile_EmptyDeps verifies that an empty dependency lockfile
// returns complete=true with an empty slice (zero-dependency project is valid).
func TestParseComposerLockfile_EmptyDeps(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "composer.lock"),
		[]byte(composerLockEmpty), 0o644))

	deps, complete, err := parseComposerLockfile(dir)
	require.NoError(t, err)
	assert.True(t, complete, "empty composer.lock → complete=true (zero deps is valid)")
	assert.Empty(t, deps)
}

// TestParseComposerLockfile_Absent verifies that a missing composer.lock returns
// complete=false without an error (allows caller to mark scan incomplete).
func TestParseComposerLockfile_Absent(t *testing.T) {
	dir := t.TempDir()
	// No composer.lock written.

	deps, complete, err := parseComposerLockfile(dir)
	require.NoError(t, err, "absent composer.lock must not return an error")
	assert.False(t, complete, "absent composer.lock → complete=false")
	assert.Nil(t, deps)
}

// TestParseComposerLockfile_ManifestOnlyNoLock verifies that a directory with
// only composer.json (no lockfile) returns complete=false without running composer.
// This is the ACE-safe path: we detect PHP but cannot resolve transitives.
func TestParseComposerLockfile_ManifestOnlyNoLock(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "composer.json"),
		[]byte(`{"require": {"monolog/monolog": "^2.0"}}`), 0o644))
	// No composer.lock: the full closure is unknown without running composer install.

	deps, complete, err := parseComposerLockfile(dir)
	require.NoError(t, err, "manifest-only project must not return an error")
	assert.False(t, complete, "no composer.lock → complete=false → scan marked incomplete")
	assert.Nil(t, deps)
}

// TestParseComposerLockfile_Malformed verifies that a malformed JSON lockfile
// returns an error (complete=false) rather than a silent empty result.
func TestParseComposerLockfile_Malformed(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "composer.lock"),
		[]byte(`{not valid json`), 0o644))

	_, complete, err := parseComposerLockfile(dir)
	assert.False(t, complete, "malformed JSON → complete=false")
	assert.Error(t, err, "malformed JSON must return an error")
}

// TestParseComposerLockfile_SkipsIncompleteEntries verifies that packages with
// missing name or version are skipped without failing the parse.
func TestParseComposerLockfile_SkipsIncompleteEntries(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "composer.lock"),
		[]byte(composerLockWithMissingFields), 0o644))

	deps, complete, err := parseComposerLockfile(dir)
	require.NoError(t, err)
	assert.True(t, complete)
	// Only the entry with both name and version should be included.
	require.Len(t, deps, 1)
	assert.Equal(t, "monolog/monolog", deps[0].Name)
	assert.Equal(t, "2.3.5", deps[0].Version)
}

// TestParseComposerLockfile_StabilityVersions verifies that pre-release Composer
// version strings (alpha, beta, RC, patch suffixes) are preserved exactly as
// recorded in composer.lock. Version normalization is the responsibility of the
// advisory comparator (composerVersionInRangeV), not the lockfile parser.
func TestParseComposerLockfile_StabilityVersions(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "composer.lock"),
		[]byte(composerLockStabilityVersions), 0o644))

	deps, complete, err := parseComposerLockfile(dir)
	require.NoError(t, err)
	assert.True(t, complete)
	require.Len(t, deps, 3)

	versionsByName := make(map[string]string, len(deps))
	for _, d := range deps {
		versionsByName[d.Name] = d.Version
	}
	assert.Equal(t, "2.0.0-alpha1", versionsByName["vendor/alpha-pkg"])
	assert.Equal(t, "3.1.0-RC2", versionsByName["vendor/rc-pkg"])
	assert.Equal(t, "1.5.0-beta.3", versionsByName["vendor/beta-pkg"])
}

// ── fixtures ──────────────────────────────────────────────────────────────────

// composerLockRuntimeAndDev is a composer.lock with two runtime deps and one dev dep.
const composerLockRuntimeAndDev = `{
    "packages": [
        {
            "name": "monolog/monolog",
            "version": "2.3.5",
            "source": {"type": "git", "url": "https://github.com/Seldaek/monolog.git", "reference": "abc123"}
        },
        {
            "name": "symfony/http-foundation",
            "version": "5.4.0",
            "source": {"type": "git", "url": "https://github.com/symfony/http-foundation.git", "reference": "def456"}
        }
    ],
    "packages-dev": [
        {
            "name": "phpunit/phpunit",
            "version": "9.5.10",
            "source": {"type": "git", "url": "https://github.com/sebastianbergmann/phpunit.git", "reference": "ghi789"}
        }
    ]
}`

// composerLockRuntimeOnly is a minimal lockfile with only a runtime dependency.
const composerLockRuntimeOnly = `{
    "packages": [
        {"name": "guzzlehttp/guzzle", "version": "7.4.5"}
    ],
    "packages-dev": []
}`

// composerLockDevOnly is a lockfile with only dev packages (e.g., tools-only project).
const composerLockDevOnly = `{
    "packages": [],
    "packages-dev": [
        {"name": "phpunit/phpunit", "version": "9.5.10"}
    ]
}`

// composerLockEmpty is a valid lockfile with no dependencies at all.
const composerLockEmpty = `{
    "packages": [],
    "packages-dev": []
}`

// composerLockWithMissingFields contains entries missing name or version —
// these must be skipped rather than causing parse failure.
const composerLockWithMissingFields = `{
    "packages": [
        {"name": "monolog/monolog", "version": "2.3.5"},
        {"name": "", "version": "1.0.0"},
        {"name": "missing-version/pkg", "version": ""}
    ],
    "packages-dev": []
}`

// composerLockStabilityVersions exercises Composer pre-release version formats.
// The parser must preserve the version strings exactly as recorded in the lockfile;
// the advisory comparator is responsible for interpreting them.
const composerLockStabilityVersions = `{
    "packages": [
        {"name": "vendor/alpha-pkg", "version": "2.0.0-alpha1"},
        {"name": "vendor/rc-pkg", "version": "3.1.0-RC2"},
        {"name": "vendor/beta-pkg", "version": "1.5.0-beta.3"}
    ],
    "packages-dev": []
}`
