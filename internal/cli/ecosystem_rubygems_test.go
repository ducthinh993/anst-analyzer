package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/commit0-dev/commit0-analyzer/internal/advisory"
)

// ── adapter registration ──────────────────────────────────────────────────────

// TestRubyGemsAdapterRegistered verifies that the RubyGems lockfile-static adapter is
// registered in the global registry with the expected metadata.
func TestRubyGemsAdapterRegistered(t *testing.T) {
	var found *EcosystemAdapter
	for _, a := range EcosystemAdapters() {
		if a.Language == "ruby" {
			a := a
			found = &a
			break
		}
	}
	require.NotNil(t, found, "RubyGems adapter with Language=ruby must be registered")
	assert.Equal(t, advisory.EcosystemRubyGems, found.Ecosystem, "Ecosystem must be 'RubyGems'")
	assert.Nil(t, found.NormalizeName, "NormalizeName must be nil (RubyGems uses canonical casing from rubygems.org)")
	assert.Contains(t, found.DetectFiles, "Gemfile.lock", "Gemfile.lock must be in DetectFiles")
	assert.Contains(t, found.DetectFiles, "Gemfile", "Gemfile must be in DetectFiles for manifest-only detection")
}

// ── detectEcosystems integration ─────────────────────────────────────────────

// TestDetectEcosystems_GemfileLock verifies that Gemfile.lock triggers Ruby ecosystem detection.
func TestDetectEcosystems_GemfileLock(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Gemfile.lock"),
		[]byte(gemfileLockRailsApp), 0o644))

	eco := detectEcosystems(dir)
	assert.True(t, eco.active("ruby"), "Gemfile.lock present → Ruby ecosystem detected")
	assert.False(t, eco.active("go"), "no go.mod → Go not detected")
	assert.False(t, eco.active("php"), "no composer.lock → PHP not detected")
}

// TestDetectEcosystems_GemfileManifestOnly verifies that Gemfile alone triggers
// Ruby detection (manifest-only project; scan will be marked incomplete).
func TestDetectEcosystems_GemfileManifestOnly(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Gemfile"),
		[]byte("source 'https://rubygems.org'\ngem 'rails', '~> 7.0'\n"), 0o644))

	eco := detectEcosystems(dir)
	assert.True(t, eco.active("ruby"), "Gemfile present → Ruby ecosystem detected (incomplete scan)")
}

// ── parseGemfileLock ──────────────────────────────────────────────────────────

// TestParseGemfileLock_RailsApp verifies that a typical Rails app lockfile is
// parsed into the full transitive closure with correct names and versions.
// TestParseGemfileLock_PlatformVariantsDedup verifies that a gem listed once per
// resolved platform (e.g. "nokogiri (1.19.0-x86_64-linux-gnu)") collapses to a
// single dependency at its base version. Without platform stripping + dedup, each
// variant matches the same advisories and multiplies the finding count.
func TestParseGemfileLock_PlatformVariantsDedup(t *testing.T) {
	dir := t.TempDir()
	lock := `GEM
  remote: https://rubygems.org/
  specs:
    nokogiri (1.19.0)
    nokogiri (1.19.0-aarch64-linux-gnu)
    nokogiri (1.19.0-arm64-darwin)
    nokogiri (1.19.0-x86_64-linux-gnu)
    rack (3.0.0)

PLATFORMS
  ruby
  x86_64-linux

DEPENDENCIES
  nokogiri
  rack
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Gemfile.lock"), []byte(lock), 0o644))

	deps, complete, err := parseGemfileLock(dir)
	require.NoError(t, err)
	assert.True(t, complete)

	var nokogiri []ResolvedDep
	for _, d := range deps {
		if d.Name == "nokogiri" {
			nokogiri = append(nokogiri, d)
		}
	}
	require.Len(t, nokogiri, 1, "nokogiri's four platform variants must collapse to one dependency")
	assert.Equal(t, "1.19.0", nokogiri[0].Version, "platform suffix must be stripped to the base Gem::Version")
}

func TestParseGemfileLock_RailsApp(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Gemfile.lock"),
		[]byte(gemfileLockRailsApp), 0o644))

	deps, complete, err := parseGemfileLock(dir)
	require.NoError(t, err)
	assert.True(t, complete, "Gemfile.lock present → complete=true")

	// Build a map for convenient lookup.
	byName := make(map[string]ResolvedDep, len(deps))
	for _, d := range deps {
		byName[d.Name] = d
	}

	// All gems from the GEM/specs section must be present.
	require.Contains(t, byName, "rails")
	assert.Equal(t, "7.0.4", byName["rails"].Version)
	assert.Equal(t, "runtime", byName["rails"].DepType, "all deps tagged runtime (group info not in Gemfile.lock)")

	require.Contains(t, byName, "actionmailer")
	assert.Equal(t, "7.0.4", byName["actionmailer"].Version)
	assert.Equal(t, "runtime", byName["actionmailer"].DepType)

	require.Contains(t, byName, "activesupport")
	assert.Equal(t, "7.0.4.3", byName["activesupport"].Version)
	assert.Equal(t, "runtime", byName["activesupport"].DepType)

	// rspec-rails is a dev gem in the Gemfile, but Gemfile.lock does not encode
	// that; it must also appear with DepType="runtime" (conservative default).
	require.Contains(t, byName, "rspec-rails")
	assert.Equal(t, "runtime", byName["rspec-rails"].DepType, "dev gems tagged runtime (group info deferred to v1.1)")
}

// TestParseGemfileLock_AllDepTypes verifies that all resolved gems — regardless
// of their group in the Gemfile — receive DepType="runtime" because Gemfile.lock
// does not encode group membership.
func TestParseGemfileLock_AllDepTypes(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Gemfile.lock"),
		[]byte(gemfileLockMixedGroups), 0o644))

	deps, complete, err := parseGemfileLock(dir)
	require.NoError(t, err)
	assert.True(t, complete)

	for _, d := range deps {
		assert.Equal(t, "runtime", d.DepType,
			"gem %q: all deps must be tagged runtime (Gemfile.lock has no group annotations)", d.Name)
	}
}

// TestParseGemfileLock_PreReleaseVersions verifies that pre-release Gem::Version
// strings (letter-segment, rc, beta, pre) are preserved exactly as recorded in
// Gemfile.lock. Version interpretation is the comparator's responsibility.
func TestParseGemfileLock_PreReleaseVersions(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Gemfile.lock"),
		[]byte(gemfileLockPreRelease), 0o644))

	deps, complete, err := parseGemfileLock(dir)
	require.NoError(t, err)
	assert.True(t, complete)

	byName := make(map[string]string, len(deps))
	for _, d := range deps {
		byName[d.Name] = d.Version
	}

	assert.Equal(t, "1.0.0.beta1", byName["my-beta-gem"])
	assert.Equal(t, "2.3.0.rc2", byName["my-rc-gem"])
	assert.Equal(t, "0.9.0.pre", byName["my-pre-gem"])
}

// TestParseGemfileLock_HyphenatedAndDottedNames verifies that gem names
// containing hyphens and dots (common in the RubyGems ecosystem) are parsed
// correctly.
func TestParseGemfileLock_HyphenatedAndDottedNames(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Gemfile.lock"),
		[]byte(gemfileLockSpecialNames), 0o644))

	deps, complete, err := parseGemfileLock(dir)
	require.NoError(t, err)
	assert.True(t, complete)

	byName := make(map[string]string, len(deps))
	for _, d := range deps {
		byName[d.Name] = d.Version
	}

	assert.Equal(t, "0.3.2", byName["net-http"])
	assert.Equal(t, "3.24.4", byName["google-protobuf"])
	assert.Equal(t, "1.2.0", byName["rack_attack"])
}

// TestParseGemfileLock_Empty verifies that an empty Gemfile.lock (valid for a
// zero-dependency project) returns complete=true with an empty slice.
func TestParseGemfileLock_Empty(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Gemfile.lock"),
		[]byte(gemfileLockEmpty), 0o644))

	deps, complete, err := parseGemfileLock(dir)
	require.NoError(t, err)
	assert.True(t, complete, "empty Gemfile.lock → complete=true (zero deps is valid)")
	assert.Empty(t, deps)
}

// TestParseGemfileLock_Absent verifies that a missing Gemfile.lock returns
// complete=false without an error (allows caller to mark scan incomplete).
func TestParseGemfileLock_Absent(t *testing.T) {
	dir := t.TempDir()
	// No Gemfile.lock written.

	deps, complete, err := parseGemfileLock(dir)
	require.NoError(t, err, "absent Gemfile.lock must not return an error")
	assert.False(t, complete, "absent Gemfile.lock → complete=false")
	assert.Nil(t, deps)
}

// TestParseGemfileLock_GemfileOnlyNoLock verifies that a directory with only
// a Gemfile (no lockfile) returns complete=false without evaluating the Gemfile.
// This is the ACE-safe path: we detect Ruby but cannot resolve transitives.
func TestParseGemfileLock_GemfileOnlyNoLock(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Gemfile"),
		[]byte("source 'https://rubygems.org'\ngem 'rails', '~> 7.0'\n"), 0o644))
	// No Gemfile.lock: the full closure is unknown without running bundle install.

	deps, complete, err := parseGemfileLock(dir)
	require.NoError(t, err, "manifest-only project must not return an error")
	assert.False(t, complete, "no Gemfile.lock → complete=false → scan marked incomplete")
	assert.Nil(t, deps)
}

// TestParseGemfileLock_SkipsDependencySubLines verifies that the parser does
// NOT include gem constraint sub-lines (6-space indent) as separate gems.
// Those lines describe version requirements on a gem's dependencies, not new gems.
func TestParseGemfileLock_SkipsDependencySubLines(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Gemfile.lock"),
		[]byte(gemfileLockWithSubLines), 0o644))

	deps, complete, err := parseGemfileLock(dir)
	require.NoError(t, err)
	assert.True(t, complete)

	// Only the top-level spec lines (4-space indent) should produce entries.
	// Sub-dependency constraint lines (6-space indent) must be skipped.
	byName := make(map[string]string, len(deps))
	for _, d := range deps {
		byName[d.Name] = d.Version
	}

	assert.Contains(t, byName, "rails", "rails spec must be parsed")
	assert.Contains(t, byName, "actionpack", "actionpack spec must be parsed")
	// "activesupport" appears as a sub-line constraint under actionpack;
	// it is also a top-level spec → should appear exactly once.
	assert.Contains(t, byName, "activesupport", "activesupport spec must be parsed")
	// "~> 7.0" is NOT a gem name; it must not appear as a parsed dep.
	assert.NotContains(t, byName, "~>")
	assert.NotContains(t, byName, "actionview (= 7.0.4)")
}

// TestParseGemfileLock_MultipleGEMSections verifies that the parser handles
// lockfiles with PATH sections (local gem sources) correctly.
// PATH gems are skipped because they are local gems with no OSV index entry.
// Only gems in the GEM section are returned.
func TestParseGemfileLock_MultipleGEMSections(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Gemfile.lock"),
		[]byte(gemfileLockWithPath), 0o644))

	deps, complete, err := parseGemfileLock(dir)
	require.NoError(t, err)
	assert.True(t, complete)

	byName := make(map[string]string, len(deps))
	for _, d := range deps {
		byName[d.Name] = d.Version
	}

	// The GEM section gem should be parsed.
	assert.Contains(t, byName, "rails")
	assert.Equal(t, "7.0.4", byName["rails"])

	// PATH-sourced gems are skipped: they are local gems without OSV entries.
	assert.NotContains(t, byName, "my-local-gem", "PATH gems must not appear in the closure")
}

// TestParseGemfileLock_GITSection verifies that gems from a GIT section are
// included in the resolved closure. GIT-pinned gems carry real names and versions
// that can match published OSV advisories; silently dropping them would produce a
// false-clean result (unknown ≠ safe).
func TestParseGemfileLock_GITSection(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Gemfile.lock"),
		[]byte(gemfileLockWithGIT), 0o644))

	deps, complete, err := parseGemfileLock(dir)
	require.NoError(t, err)
	assert.True(t, complete, "Gemfile.lock with GIT section must parse as complete=true")

	byName := make(map[string]string, len(deps))
	for _, d := range deps {
		byName[d.Name] = d.Version
	}

	// GEM section gem must be present.
	assert.Equal(t, "7.0.4", byName["rails"], "GEM section gem must be included in closure")
	// GIT section gem must also be included (has a real name+version, may have OSV advisory).
	assert.Equal(t, "0.5.0", byName["my-git-gem"], "GIT section gem must be included in closure")
}

// TestParseGemfileLock_CRLF verifies that a Gemfile.lock with Windows/DOS
// CRLF line endings (\r\n) is parsed identically to its LF-only equivalent.
// A CRLF file produces scanner lines ending with \r; without stripping the \r,
// gemSpecRe anchored at \)$ would never match and the parser would silently
// return an empty closure with complete=true — a cardinal false-clean.
func TestParseGemfileLock_CRLF(t *testing.T) {
	dir := t.TempDir()
	crlf := strings.ReplaceAll(gemfileLockRailsApp, "\n", "\r\n")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Gemfile.lock"), []byte(crlf), 0o644))

	deps, complete, err := parseGemfileLock(dir)
	require.NoError(t, err)
	assert.True(t, complete, "CRLF Gemfile.lock must parse as complete=true")
	assert.NotEmpty(t, deps, "CRLF Gemfile.lock must produce a non-empty closure")

	byName := make(map[string]string, len(deps))
	for _, d := range deps {
		byName[d.Name] = d.Version
	}
	assert.Equal(t, "7.0.4", byName["rails"], "rails must be parsed from CRLF lockfile")
	assert.Equal(t, "7.0.4.3", byName["activesupport"], "transitive deps must be parsed from CRLF lockfile")
}

// TestParseGemfileLock_BOM verifies that a Gemfile.lock with a leading UTF-8 BOM
// (0xEF 0xBB 0xBF) is parsed correctly. A BOM-prefixed first line would corrupt the
// section header ("GEM" → "\xEF\xBB\xBFGEM"), causing no gems to be recognised
// and silently returning complete=true with zero deps — the same false-clean as CRLF.
func TestParseGemfileLock_BOM(t *testing.T) {
	dir := t.TempDir()
	bom := "\xEF\xBB\xBF" + gemfileLockRailsApp
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Gemfile.lock"), []byte(bom), 0o644))

	deps, complete, err := parseGemfileLock(dir)
	require.NoError(t, err)
	assert.True(t, complete, "BOM-prefixed Gemfile.lock must parse as complete=true")
	assert.NotEmpty(t, deps, "BOM-prefixed Gemfile.lock must produce a non-empty closure")

	byName := make(map[string]string, len(deps))
	for _, d := range deps {
		byName[d.Name] = d.Version
	}
	assert.Equal(t, "7.0.4", byName["rails"], "rails must be parsed from BOM-prefixed lockfile")
}

// ── fixtures ──────────────────────────────────────────────────────────────────

// gemfileLockRailsApp is a representative Rails 7 application Gemfile.lock.
// It includes transitive deps and a dev gem (rspec-rails) to exercise the
// "all runtime" dep-type tagging (group info not in lockfile).
const gemfileLockRailsApp = `GEM
  remote: https://rubygems.org/
  specs:
    actionmailer (7.0.4)
      actionpack (= 7.0.4)
      actionview (= 7.0.4)
      mail (~> 2.5, >= 2.5.4)
    actionpack (7.0.4)
      actionview (= 7.0.4)
      activesupport (= 7.0.4)
      rack (~> 2.0, >= 2.0.8)
    actionview (7.0.4)
      activesupport (= 7.0.4)
    activesupport (7.0.4.3)
      concurrent-ruby (~> 1.0, >= 1.0.2)
      i18n (>= 1.6, < 2)
    concurrent-ruby (1.2.2)
    i18n (1.14.1)
      concurrent-ruby (~> 1.0)
    mail (2.8.1)
      mini_mime (>= 0.1.1)
    mini_mime (1.1.5)
    rack (2.2.8)
    rails (7.0.4)
      actionmailer (= 7.0.4)
      actionpack (= 7.0.4)
      actionview (= 7.0.4)
      activesupport (= 7.0.4)
    rspec-rails (6.0.3)
      actionpack (>= 6.1)
      activesupport (>= 6.1)
      rspec-core (~> 3.10)
    rspec-core (3.12.2)

PLATFORMS
  arm64-darwin-21
  x86_64-linux

DEPENDENCIES
  rails (~> 7.0)
  rspec-rails (~> 6.0)

BUNDLED WITH
   2.4.12
`

// gemfileLockMixedGroups simulates a lockfile that would come from a project with
// mixed runtime/development groups. Since Gemfile.lock does not encode groups,
// all entries must be tagged "runtime".
const gemfileLockMixedGroups = `GEM
  remote: https://rubygems.org/
  specs:
    rails (7.0.4)
    rspec (3.12.0)
    factory_bot (6.2.1)
    puma (5.6.7)

PLATFORMS
  x86_64-linux

DEPENDENCIES
  factory_bot
  puma
  rails
  rspec

BUNDLED WITH
   2.4.12
`

// gemfileLockPreRelease exercises Gem::Version pre-release formats that use
// letter segments and dotted pre-release suffixes.
const gemfileLockPreRelease = `GEM
  remote: https://rubygems.org/
  specs:
    my-beta-gem (1.0.0.beta1)
    my-pre-gem (0.9.0.pre)
    my-rc-gem (2.3.0.rc2)

PLATFORMS
  x86_64-linux

DEPENDENCIES
  my-beta-gem
  my-pre-gem
  my-rc-gem

BUNDLED WITH
   2.4.12
`

// gemfileLockSpecialNames exercises gem names with hyphens, underscores, and dots.
const gemfileLockSpecialNames = `GEM
  remote: https://rubygems.org/
  specs:
    google-protobuf (3.24.4)
    net-http (0.3.2)
    rack_attack (1.2.0)

PLATFORMS
  x86_64-linux

DEPENDENCIES
  google-protobuf
  net-http
  rack_attack

BUNDLED WITH
   2.4.12
`

// gemfileLockEmpty is a minimal valid Gemfile.lock with no gems (zero-dep project).
const gemfileLockEmpty = `GEM
  remote: https://rubygems.org/
  specs:

PLATFORMS
  x86_64-linux

DEPENDENCIES

BUNDLED WITH
   2.4.12
`

// gemfileLockWithSubLines has a gem spec section where each spec line is followed
// by constraint sub-lines (6-space indent). The parser must not treat those as gems.
const gemfileLockWithSubLines = `GEM
  remote: https://rubygems.org/
  specs:
    actionpack (7.0.4)
      actionview (= 7.0.4)
      activesupport (= 7.0.4)
    actionview (7.0.4)
      activesupport (= 7.0.4)
    activesupport (7.0.4)
    rails (7.0.4)
      actionpack (= 7.0.4)

PLATFORMS
  x86_64-linux

DEPENDENCIES
  rails (~> 7.0)

BUNDLED WITH
   2.4.12
`

// gemfileLockWithPath is a lockfile that includes a PATH section (local gem source)
// in addition to the standard GEM section. PATH gems are local and have no OSV entry,
// so the parser must skip them and return only GEM section gems.
const gemfileLockWithPath = `PATH
  remote: .
  specs:
    my-local-gem (0.1.0)

GEM
  remote: https://rubygems.org/
  specs:
    rails (7.0.4)

PLATFORMS
  x86_64-linux

DEPENDENCIES
  my-local-gem!
  rails (~> 7.0)

BUNDLED WITH
   2.4.12
`

// gemfileLockWithGIT is a lockfile that includes a GIT section (git-sourced gem)
// in addition to the standard GEM section. Unlike PATH gems, GIT-pinned gems carry
// real names and versions that may match published OSV advisories, so they must be
// included in the resolved closure (conservative: no false-clean omissions).
const gemfileLockWithGIT = `GIT
  remote: https://github.com/owner/my-git-gem.git
  revision: abc123def456789abc123def456789abc123def4
  branch: main
  specs:
    my-git-gem (0.5.0)

GEM
  remote: https://rubygems.org/
  specs:
    rails (7.0.4)

PLATFORMS
  x86_64-linux

DEPENDENCIES
  my-git-gem!
  rails (~> 7.0)

BUNDLED WITH
   2.4.12
`
