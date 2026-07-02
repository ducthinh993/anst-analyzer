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

// TestHexAdapterRegistered verifies that the Hex lockfile-static adapter is registered
// in the global registry with the expected metadata.
func TestHexAdapterRegistered(t *testing.T) {
	var found *EcosystemAdapter
	for _, a := range EcosystemAdapters() {
		if a.Language == "elixir" {
			a := a
			found = &a
			break
		}
	}
	require.NotNil(t, found, "Hex adapter with Language=elixir must be registered")
	assert.Equal(t, advisory.EcosystemHex, found.Ecosystem, "Ecosystem must be 'Hex'")
	assert.Nil(t, found.NormalizeName, "NormalizeName must be nil (Hex names are case-sensitive)")
	assert.Contains(t, found.DetectFiles, "mix.lock", "mix.lock must be in DetectFiles")
	assert.Contains(t, found.DetectFiles, "rebar.lock", "rebar.lock must be in DetectFiles")
}

// ── detectEcosystems integration ─────────────────────────────────────────────

// TestDetectEcosystems_MixLock verifies that mix.lock triggers Elixir ecosystem detection.
func TestDetectEcosystems_MixLock(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "mix.lock"),
		[]byte(mixLockPhoenix), 0o644))

	eco := detectEcosystems(dir)
	assert.True(t, eco.active("elixir"), "mix.lock present → Elixir ecosystem detected")
	assert.False(t, eco.active("go"), "no go.mod → Go not detected")
	assert.False(t, eco.active("ruby"), "no Gemfile.lock → Ruby not detected")
}

// TestDetectEcosystems_RebarLock verifies that rebar.lock alone triggers Elixir detection.
func TestDetectEcosystems_RebarLock(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "rebar.lock"),
		[]byte(rebarLockCowboy), 0o644))

	eco := detectEcosystems(dir)
	assert.True(t, eco.active("elixir"), "rebar.lock present → Elixir ecosystem detected")
	assert.False(t, eco.active("go"), "no go.mod → Go not detected")
}

// ── parseMixLock ──────────────────────────────────────────────────────────────

// TestParseMixLock_Phoenix verifies that a typical Phoenix/Elixir project mix.lock
// is parsed into the full resolved closure with correct names and versions.
func TestParseMixLock_Phoenix(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "mix.lock"),
		[]byte(mixLockPhoenix), 0o644))

	deps, complete, err := parseMixLock(dir)
	require.NoError(t, err)
	assert.True(t, complete, "mix.lock present → complete=true")

	byName := make(map[string]ResolvedDep, len(deps))
	for _, d := range deps {
		byName[d.Name] = d
	}

	// All :hex entries must be present.
	require.Contains(t, byName, "castore")
	assert.Equal(t, "1.0.6", byName["castore"].Version)

	require.Contains(t, byName, "certifi")
	assert.Equal(t, "2.9.0", byName["certifi"].Version)

	require.Contains(t, byName, "jason")
	assert.Equal(t, "1.4.1", byName["jason"].Version)

	require.Contains(t, byName, "mint")
	assert.Equal(t, "1.5.2", byName["mint"].Version)

	require.Contains(t, byName, "telemetry")
	assert.Equal(t, "1.2.1", byName["telemetry"].Version)
}

// TestParseMixLock_DepTypeUnknown verifies that all mix.lock deps carry DepType=""
// because mix.lock does not encode the :only scope from mix.exs. The
// mergeDepType contract treats "" as "runtime" (conservative: unknown ≠ dev).
func TestParseMixLock_DepTypeUnknown(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "mix.lock"),
		[]byte(mixLockPhoenix), 0o644))

	deps, complete, err := parseMixLock(dir)
	require.NoError(t, err)
	assert.True(t, complete)

	for _, d := range deps {
		assert.Equal(t, "", d.DepType,
			"dep %q: DepType must be empty string (mix.lock has no :only scope; "+
				"mergeDepType will treat it as runtime — conservative default)", d.Name)
	}
}

// TestParseMixLock_SkipsGitEntries verifies that :git entries in mix.lock are
// not included in the resolved closure. Git-sourced deps have no Hex registry
// version and cannot match OSV Hex advisories.
func TestParseMixLock_SkipsGitEntries(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "mix.lock"),
		[]byte(mixLockWithGitDep), 0o644))

	deps, complete, err := parseMixLock(dir)
	require.NoError(t, err)
	assert.True(t, complete)

	byName := make(map[string]string, len(deps))
	for _, d := range deps {
		byName[d.Name] = d.Version
	}

	// :hex dep must be present.
	assert.Contains(t, byName, "jason", ":hex dep must be in closure")
	assert.Equal(t, "1.4.1", byName["jason"])

	// :git dep must be skipped — no Hex registry version → cannot match OSV advisories.
	assert.NotContains(t, byName, "my_git_dep",
		":git dep must be excluded (no Hex registry version → cannot match OSV Hex advisories)")
}

// TestParseMixLock_SkipsPathEntries verifies that :path entries in mix.lock are
// not included in the resolved closure. Path deps are local packages with no
// Hex registry identity.
func TestParseMixLock_SkipsPathEntries(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "mix.lock"),
		[]byte(mixLockWithPathDep), 0o644))

	deps, complete, err := parseMixLock(dir)
	require.NoError(t, err)
	assert.True(t, complete)

	byName := make(map[string]string, len(deps))
	for _, d := range deps {
		byName[d.Name] = d.Version
	}

	assert.Contains(t, byName, "jason", ":hex dep must be in closure")
	assert.NotContains(t, byName, "my_local_dep",
		":path dep must be excluded (local package, no Hex registry entry)")
}

// TestParseMixLock_Empty verifies that an empty mix.lock (zero :hex deps) returns
// complete=true with an empty dep list. This is valid for a project with no deps.
func TestParseMixLock_Empty(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "mix.lock"), []byte(mixLockEmpty), 0o644))

	deps, complete, err := parseMixLock(dir)
	require.NoError(t, err)
	assert.True(t, complete, "empty mix.lock → complete=true (zero deps is valid)")
	assert.Empty(t, deps)
}

// TestParseMixLock_MalformedNoMarker verifies that a present-but-unparseable mix.lock
// (non-empty content without the %{ map-open marker that every valid mix.lock must have)
// returns complete=false. This upholds the 'unknown ≠ safe' invariant: returning a clean
// empty closure for content we could not parse would silently drop all Hex advisories
// (false-clean). Mirrors the parseRebarLock behaviour on unrecognised format variants.
func TestParseMixLock_MalformedNoMarker(t *testing.T) {
	dir := t.TempDir()
	// Write a non-empty file that lacks the %{ map-open marker all valid mix.lock
	// files contain — simulates a corrupted file or an unrecognised format variant.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "mix.lock"),
		[]byte("# this is not a valid mix.lock\ncastore 1.0.6\ncertifi 2.9.0\n"), 0o644))

	deps, complete, err := parseMixLock(dir)
	require.NoError(t, err)
	assert.False(t, complete,
		"present mix.lock without %%{ marker must return complete=false (unknown ≠ safe)")
	assert.Nil(t, deps)
}

// TestParseMixLock_EmptyMapMarker verifies that a genuinely empty mix.lock (%{})
// returns complete=true with an empty dep list. %{ is recognisable as a valid
// (empty) Elixir map — this is what `mix deps.get` writes for a zero-dep project.
func TestParseMixLock_EmptyMapMarker(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "mix.lock"), []byte("%{}\n"), 0o644))

	deps, complete, err := parseMixLock(dir)
	require.NoError(t, err)
	assert.True(t, complete, "empty %{} mix.lock → complete=true (legitimate zero-dep project)")
	assert.Empty(t, deps)
}

// TestParseMixLock_Absent verifies that a missing mix.lock returns complete=false
// without an error (caller must mark scan incomplete; no tool run = ACE risk).
func TestParseMixLock_Absent(t *testing.T) {
	dir := t.TempDir()
	// No mix.lock written.

	deps, complete, err := parseMixLock(dir)
	require.NoError(t, err, "absent mix.lock must not return an error")
	assert.False(t, complete, "absent mix.lock → complete=false")
	assert.Nil(t, deps)
}

// TestParseMixLock_CRLF verifies that a mix.lock with Windows CRLF line endings
// is parsed identically to its LF-only equivalent. A \r left at the end of
// a version field would corrupt the version string (e.g. "1.4.1\r") and cause
// false NOT_REACHABLE on any advisory range check.
func TestParseMixLock_CRLF(t *testing.T) {
	dir := t.TempDir()
	crlf := mixLockPhoenix
	crlf = string([]byte(crlf))
	// Simulate CRLF by replacing \n with \r\n.
	var result []byte
	for i := 0; i < len(crlf); i++ {
		if crlf[i] == '\n' {
			result = append(result, '\r', '\n')
		} else {
			result = append(result, crlf[i])
		}
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "mix.lock"), result, 0o644))

	deps, complete, err := parseMixLock(dir)
	require.NoError(t, err)
	assert.True(t, complete, "CRLF mix.lock must parse as complete=true")
	assert.NotEmpty(t, deps, "CRLF mix.lock must produce a non-empty closure")

	byName := make(map[string]string, len(deps))
	for _, d := range deps {
		byName[d.Name] = d.Version
	}
	assert.Equal(t, "1.4.1", byName["jason"], "version must not contain trailing \\r")
	assert.Equal(t, "1.2.1", byName["telemetry"], "telemetry version must parse correctly")
}

// ── parseRebarLock ───────────────────────────────────────────────────────────

// TestParseRebarLock_Cowboy verifies that a typical Erlang/Rebar3 rebar.lock
// is parsed into the full resolved closure with correct names and versions.
func TestParseRebarLock_Cowboy(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "rebar.lock"),
		[]byte(rebarLockCowboy), 0o644))

	deps, complete, err := parseRebarLock(dir)
	require.NoError(t, err)
	assert.True(t, complete, "rebar.lock present → complete=true")

	byName := make(map[string]string, len(deps))
	for _, d := range deps {
		byName[d.Name] = d.Version
	}

	require.Contains(t, byName, "cowboy")
	assert.Equal(t, "2.10.0", byName["cowboy"])

	require.Contains(t, byName, "ranch")
	assert.Equal(t, "1.8.0", byName["ranch"])

	require.Contains(t, byName, "cowlib")
	assert.Equal(t, "2.12.1", byName["cowlib"])
}

// TestParseRebarLock_DepTypeUnknown verifies that all rebar.lock deps carry DepType=""
// (rebar.lock does not encode dep-type; mergeDepType treats "" as "runtime").
func TestParseRebarLock_DepTypeUnknown(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "rebar.lock"),
		[]byte(rebarLockCowboy), 0o644))

	deps, complete, err := parseRebarLock(dir)
	require.NoError(t, err)
	assert.True(t, complete)

	for _, d := range deps {
		assert.Equal(t, "", d.DepType,
			"dep %q: DepType must be empty string (rebar.lock encodes no dep-type)", d.Name)
	}
}

// TestParseRebarLock_SkipsGitEntries verifies that {git,...} entries in rebar.lock
// are not included in the resolved closure (no Hex registry version).
func TestParseRebarLock_SkipsGitEntries(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "rebar.lock"),
		[]byte(rebarLockWithGitDep), 0o644))

	deps, complete, err := parseRebarLock(dir)
	require.NoError(t, err)
	assert.True(t, complete)

	byName := make(map[string]string, len(deps))
	for _, d := range deps {
		byName[d.Name] = d.Version
	}

	assert.Contains(t, byName, "cowboy", "pkg dep must be in closure")
	assert.NotContains(t, byName, "my_git_dep",
		"git dep must be excluded (no Hex registry version)")
}

// TestParseRebarLock_Absent verifies that a missing rebar.lock returns complete=false
// without an error.
func TestParseRebarLock_Absent(t *testing.T) {
	dir := t.TempDir()

	deps, complete, err := parseRebarLock(dir)
	require.NoError(t, err, "absent rebar.lock must not return an error")
	assert.False(t, complete, "absent rebar.lock → complete=false")
	assert.Nil(t, deps)
}

// TestParseRebarLock_PresentButNoMatches verifies that a rebar.lock file that is
// present but contains no recognisable {pkg,...} entries returns complete=false.
// This upholds the 'unknown ≠ safe' invariant: we cannot distinguish an empty
// lockfile (no Hex deps) from an unrecognised format, so returning complete=true
// with zero deps would silently drop all advisories (false-clean).
func TestParseRebarLock_PresentButNoMatches(t *testing.T) {
	dir := t.TempDir()
	// Write a file that is syntactically plausible rebar.lock but has no {pkg,...}
	// entries — simulates a pure-git-dep project or an unrecognised format variant.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "rebar.lock"),
		[]byte("{[], [1,0,0]}.\n"), 0o644))

	deps, complete, err := parseRebarLock(dir)
	require.NoError(t, err)
	assert.False(t, complete,
		"present rebar.lock with no pkg entries must return complete=false (unknown ≠ safe)")
	assert.Nil(t, deps)
}

// TestParseRebarLock_RealBinaryLiteralFormat verifies that parseRebarLock correctly
// parses the actual rebar3 output format, where all string values are Erlang binary
// literals (<<"...">>) rather than plain double-quoted atoms.
// This is the format written by every real rebar3 invocation; the previous regex
// matched plain-quoted strings (a format rebar3 never produces) so it silently
// returned zero deps on every real Erlang/rebar3 project (false-clean).
func TestParseRebarLock_RealBinaryLiteralFormat(t *testing.T) {
	// Real rebar3 lock entry: {<<"name">>,{pkg,<<"reg_name">>,<<"version">>},depth}
	realFormat := `{[{<<"cowboy">>,{pkg,<<"cowboy">>,<<"2.10.0">>},0},
{<<"ranch">>,{pkg,<<"ranch">>,<<"1.8.0">>},1},
{<<"my_git_dep">>,{git,"https://github.com/owner/repo.git",{branch,"main"}},0}
],
[1,0,0]}.
`
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "rebar.lock"), []byte(realFormat), 0o644))

	deps, complete, err := parseRebarLock(dir)
	require.NoError(t, err)
	assert.True(t, complete, "real rebar.lock must parse as complete=true")

	byName := make(map[string]string, len(deps))
	for _, d := range deps {
		byName[d.Name] = d.Version
	}

	assert.Equal(t, "2.10.0", byName["cowboy"], "cowboy version must be parsed from binary literal")
	assert.Equal(t, "1.8.0", byName["ranch"], "ranch version must be parsed from binary literal")
	assert.NotContains(t, byName, "my_git_dep",
		"git dep must be excluded (no Hex registry version)")
}

// TestParseRebarLock_MultiLine verifies that multi-line {pkg,...} entries (as
// rebar3 sometimes writes them for long hashes) are parsed correctly.
func TestParseRebarLock_MultiLine(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "rebar.lock"),
		[]byte(rebarLockMultiLine), 0o644))

	deps, complete, err := parseRebarLock(dir)
	require.NoError(t, err)
	assert.True(t, complete)

	byName := make(map[string]string, len(deps))
	for _, d := range deps {
		byName[d.Name] = d.Version
	}

	assert.Equal(t, "1.20.1", byName["hackney"])
	assert.Equal(t, "6.1.1", byName["idna"])
}

// ── parseHexLockfiles (combined) ─────────────────────────────────────────────

// TestParseHexLockfiles_MixOnly verifies that when only mix.lock is present,
// the combined parser returns the mix.lock closure with complete=true.
func TestParseHexLockfiles_MixOnly(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "mix.lock"),
		[]byte(mixLockPhoenix), 0o644))

	deps, complete, err := parseHexLockfiles(dir)
	require.NoError(t, err)
	assert.True(t, complete, "mix.lock present → complete=true")
	assert.NotEmpty(t, deps)

	byName := make(map[string]string, len(deps))
	for _, d := range deps {
		byName[d.Name] = d.Version
	}
	assert.Equal(t, "1.4.1", byName["jason"])
}

// TestParseHexLockfiles_RebarOnly verifies that when only rebar.lock is present,
// the combined parser returns the rebar.lock closure with complete=true.
func TestParseHexLockfiles_RebarOnly(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "rebar.lock"),
		[]byte(rebarLockCowboy), 0o644))

	deps, complete, err := parseHexLockfiles(dir)
	require.NoError(t, err)
	assert.True(t, complete, "rebar.lock present → complete=true")
	assert.NotEmpty(t, deps)

	byName := make(map[string]string, len(deps))
	for _, d := range deps {
		byName[d.Name] = d.Version
	}
	assert.Equal(t, "2.10.0", byName["cowboy"])
}

// TestParseHexLockfiles_BothPresent verifies that when both mix.lock and rebar.lock
// are present, the combined parser merges both closures.
func TestParseHexLockfiles_BothPresent(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "mix.lock"),
		[]byte(mixLockPhoenix), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "rebar.lock"),
		[]byte(rebarLockCowboy), 0o644))

	deps, complete, err := parseHexLockfiles(dir)
	require.NoError(t, err)
	assert.True(t, complete)
	assert.NotEmpty(t, deps)

	byName := make(map[string]string, len(deps))
	for _, d := range deps {
		byName[d.Name] = d.Version
	}
	// Entries from mix.lock
	assert.Equal(t, "1.4.1", byName["jason"])
	// Entries from rebar.lock
	assert.Equal(t, "2.10.0", byName["cowboy"])
}

// TestParseHexLockfiles_NeitherPresent verifies that when neither mix.lock nor
// rebar.lock exists, the combined parser returns complete=false (scan marked
// incomplete — unknown ≠ safe).
func TestParseHexLockfiles_NeitherPresent(t *testing.T) {
	dir := t.TempDir()

	deps, complete, err := parseHexLockfiles(dir)
	require.NoError(t, err, "absent lockfiles must not return an error")
	assert.False(t, complete, "no lockfile → complete=false")
	assert.Nil(t, deps)
}

// ── fixtures ──────────────────────────────────────────────────────────────────

// mixLockPhoenix is a representative mix.lock from a Phoenix/Elixir project.
// It exercises the :hex entry format, the :rebar3 vs :mix manager distinction,
// and deps with both short and longer version strings.
const mixLockPhoenix = `%{"castore": {:hex, :castore, "1.0.6", "ffc42f110ebfdafab6d5b9d1df6c9f20e1fb0252ade988b7c27a6d35e6e5acea", [:mix], [], "hexpm", "374f85eb2bba53f5777bd0d8bcf8db6cc7a23cdc47c28ac66ad9ac9ef64c1ac2"},
"certifi": {:hex, :certifi, "2.9.0", "6f2a475689dd47f19fb74334859d460a2dc4e3252a3324bd2111b8f0429e7e21", [:rebar3], [], "hexpm", "266da46bdb06d6c6d35fde799bcb28d36d985d424ad7c08b5212db9f525acc44"},
"jason": {:hex, :jason, "1.4.1", "af1504e35f629ddcdd6addb3513c3853991f694921b1b9368b0bd32beb9f1b63", [:mix], [], "hexpm", "fbb01ecdfd565b56261302f7e1fcc27c4fb8f32d56eab74db621fc154604a7a1"},
"mint": {:hex, :mint, "1.5.2", "4805e059f96028948870d23d7783613b7e6b0e2fb4e98d720383852a760067fd", [:mix], [], "hexpm", "d77d9e9ce4eb35941907f1d3df38d8f750c357865353e21d335bdcdf6d892a02"},
"nimble_options": {:hex, :nimble_options, "1.0.2", "92098a74df0072ff37d10c12e93d7f9c83f2fbde2ca2b1c8a7a5c821d15dd761", [:mix], [], "hexpm", "fd12a8db2021036ce12a309f26f564ec367373265b53e25403f0ee697380f1b8"},
"telemetry": {:hex, :telemetry, "1.2.1", "68fdfe8d8f05a8428483a97d7aab2f268aaff24b49e0f599faa091f1d4e7f61c", [:rebar3], [], "hexpm", "dad9ce9d8effc621708f99eac538ef1cbe05d6a874dd741de2e689c47feafed5"},
"websock": {:hex, :websock, "0.5.3", "2f69a6ebe810328555b6fe5c83fa4115ebb6513acb6c7f94600ef4875e9a8c0e", [:mix], [], "hexpm", "6105453d7fac22c712ad66fab1d45abdf049868f253cf719b625151460b8b453"},
"websock_adapter": {:hex, :websock_adapter, "0.5.5", "9dfeee8269b27e958a65b2600b91ccc4cbb2797a4dfc2a16db479b1d6d9aabee", [:mix], [], "hexpm", "4b9bd71f6011ea615dc3ed49b7d046d2e4f91f1b30af5c5b0c70de8e76b83f9"},
}
`

// mixLockEmpty is a minimal valid mix.lock with no packages (zero-dep project).
const mixLockEmpty = `%{
}
`

// mixLockWithGitDep exercises a mix.lock containing both a :hex entry and a :git
// entry. The :git entry must be excluded from the resolved closure.
const mixLockWithGitDep = `%{"jason": {:hex, :jason, "1.4.1", "af1504e35f629ddcdd6addb3513c3853991f694921b1b9368b0bd32beb9f1b63", [:mix], [], "hexpm", "fbb01ecdfd565b56261302f7e1fcc27c4fb8f32d56eab74db621fc154604a7a1"},
"my_git_dep": {:git, "https://github.com/owner/my_git_dep.git", "abcdef1234567890abcdef1234567890abcdef12", [tag: "v1.2.3"]},
}
`

// mixLockWithPathDep exercises a mix.lock containing both a :hex entry and a :path
// entry. The :path entry must be excluded (local package, no Hex registry identity).
const mixLockWithPathDep = `%{"jason": {:hex, :jason, "1.4.1", "af1504e35f629ddcdd6addb3513c3853991f694921b1b9368b0bd32beb9f1b63", [:mix], [], "hexpm", "fbb01ecdfd565b56261302f7e1fcc27c4fb8f32d56eab74db621fc154604a7a1"},
"my_local_dep": {:path, "../my_local_dep", [env: :dev]},
}
`

// rebarLockCowboy is a representative rebar.lock from an Erlang/Cowboy project.
// Uses the real rebar3 format: all string values are Erlang binary literals
// (<<"...">>) — this is the only format rebar3 ever writes to disk.
// The third element in each outer tuple (0 or 1) is the dependency depth level.
const rebarLockCowboy = "{[{<<\"cowboy\">>,{pkg,<<\"cowboy\">>,<<\"2.10.0\">>},0},\n{<<\"cowlib\">>,{pkg,<<\"cowlib\">>,<<\"2.12.1\">>},1},\n{<<\"ranch\">>,{pkg,<<\"ranch\">>,<<\"1.8.0\">>},1}\n],\n[1,0,0]}.\n"

// rebarLockWithGitDep exercises a rebar.lock containing both a {pkg,...} entry
// and a {git,...} entry. The {git,...} entry must be excluded (no Hex version).
// Uses the real rebar3 binary literal format.
const rebarLockWithGitDep = "{[{<<\"cowboy\">>,{pkg,<<\"cowboy\">>,<<\"2.10.0\">>},0},\n{<<\"my_git_dep\">>,{git,\"https://github.com/owner/my_git_dep.git\",{branch,\"main\"}},0}\n],\n[1,0,0]}.\n"

// rebarLockMultiLine exercises a rebar.lock where {pkg,...} entries span multiple
// lines (rebar3 may indent the tuple when fields are long). The regex must match
// across newlines via \s* (RE2's \s includes \n).
// Uses the real rebar3 binary literal format.
const rebarLockMultiLine = "{[{<<\"hackney\">>,\n    {pkg,\n     <<\"hackney\">>,\n     <<\"1.20.1\">>},\n    0},\n{<<\"idna\">>,{pkg,<<\"idna\">>,<<\"6.1.1\">>},1}\n],\n[1,0,0]}.\n"
