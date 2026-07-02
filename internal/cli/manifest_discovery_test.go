package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── helpers ───────────────────────────────────────────────────────────────────

// mkdirAll creates dir (and parents) under root, returning its absolute path.
func mkdirAll(t *testing.T, root string, rel string) string {
	t.Helper()
	abs := filepath.Join(root, rel)
	require.NoError(t, os.MkdirAll(abs, 0o755))
	return abs
}

// touch creates an empty file at dir/name.
func touch(t *testing.T, dir, name string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte{}, 0o644))
}

// testAdapters returns two minimal adapters for use in discovery tests:
// - "php"  → DetectFiles: ["composer.lock", "composer.json"]
// - "ruby" → DetectFiles: ["Gemfile.lock", "Gemfile"]
func testAdapters() []EcosystemAdapter {
	return []EcosystemAdapter{
		{
			Language:      "php",
			DetectFiles:   []string{"composer.lock", "composer.json"},
			ParseLockfile: func(_ string) ([]ResolvedDep, bool, error) { return nil, true, nil },
		},
		{
			Language:      "ruby",
			DetectFiles:   []string{"Gemfile.lock", "Gemfile"},
			ParseLockfile: func(_ string) ([]ResolvedDep, bool, error) { return nil, true, nil },
		},
	}
}

// testAdaptersWithGlob returns an adapter that uses a suffix-glob DetectFile.
func testAdaptersWithGlob() []EcosystemAdapter {
	return []EcosystemAdapter{
		{
			Language:      "dotnet",
			DetectFiles:   []string{"packages.lock.json", "*.csproj"},
			ParseLockfile: func(_ string) ([]ResolvedDep, bool, error) { return nil, true, nil },
		},
	}
}

// ── discoverLaneAProjectDirs ──────────────────────────────────────────────────

// TestDiscover_Empty verifies that an empty directory returns no dirs and no cap.
func TestDiscover_Empty(t *testing.T) {
	root := t.TempDir()
	dirs, capped := discoverLaneAProjectDirs(root, testAdapters())
	assert.False(t, capped)
	assert.Empty(t, dirs["php"])
	assert.Empty(t, dirs["ruby"])
}

// TestDiscover_RootOnly verifies that a matching manifest at the root is found.
func TestDiscover_RootOnly(t *testing.T) {
	root := t.TempDir()
	touch(t, root, "composer.lock")

	dirs, capped := discoverLaneAProjectDirs(root, testAdapters())
	assert.False(t, capped)
	assert.Equal(t, []string{root}, dirs["php"])
	assert.Empty(t, dirs["ruby"])
}

// TestDiscover_RootAndSubdir verifies that manifests at both root and a subdir
// are both collected.
func TestDiscover_RootAndSubdir(t *testing.T) {
	root := t.TempDir()
	touch(t, root, "Gemfile.lock") // root has Ruby

	subA := mkdirAll(t, root, "services/api")
	touch(t, subA, "composer.lock") // sub has PHP

	dirs, capped := discoverLaneAProjectDirs(root, testAdapters())
	assert.False(t, capped)
	assert.Equal(t, []string{root}, dirs["ruby"])
	assert.Equal(t, []string{subA}, dirs["php"])
}

// TestDiscover_MultipleSubdirs verifies that multiple matching subdirectories
// for the same adapter are all returned.
func TestDiscover_MultipleSubdirs(t *testing.T) {
	root := t.TempDir()
	subA := mkdirAll(t, root, "a")
	subB := mkdirAll(t, root, "b")
	subC := mkdirAll(t, root, "a/c")

	touch(t, subA, "composer.lock")
	touch(t, subB, "composer.lock")
	touch(t, subC, "composer.lock")

	dirs, capped := discoverLaneAProjectDirs(root, testAdapters())
	assert.False(t, capped)
	assert.ElementsMatch(t, []string{subA, subB, subC}, dirs["php"])
}

// TestDiscover_PolygotSubdir verifies that a subdir matching both adapters appears
// in both adapters' lists.
func TestDiscover_PolyglotSubdir(t *testing.T) {
	root := t.TempDir()
	sub := mkdirAll(t, root, "app")
	touch(t, sub, "composer.lock")
	touch(t, sub, "Gemfile.lock")

	dirs, capped := discoverLaneAProjectDirs(root, testAdapters())
	assert.False(t, capped)
	assert.Equal(t, []string{sub}, dirs["php"])
	assert.Equal(t, []string{sub}, dirs["ruby"])
}

// TestDiscover_IgnoredDirs_NodeModules verifies that node_modules is never descended.
func TestDiscover_IgnoredDirs_NodeModules(t *testing.T) {
	root := t.TempDir()
	// composer.lock inside node_modules — must be ignored
	evil := mkdirAll(t, root, "node_modules/some-pkg")
	touch(t, evil, "composer.lock")

	dirs, capped := discoverLaneAProjectDirs(root, testAdapters())
	assert.False(t, capped)
	assert.Empty(t, dirs["php"], "node_modules must be skipped")
}

// TestDiscover_IgnoredDirs_Vendor verifies that vendor is never descended.
func TestDiscover_IgnoredDirs_Vendor(t *testing.T) {
	root := t.TempDir()
	evil := mkdirAll(t, root, "vendor/github.com/foo")
	touch(t, evil, "composer.lock")

	dirs, _ := discoverLaneAProjectDirs(root, testAdapters())
	assert.Empty(t, dirs["php"], "vendor must be skipped")
}

// TestDiscover_IgnoredDirs_Build verifies that build is skipped.
func TestDiscover_IgnoredDirs_Build(t *testing.T) {
	root := t.TempDir()
	evil := mkdirAll(t, root, "build/output")
	touch(t, evil, "Gemfile.lock")

	dirs, _ := discoverLaneAProjectDirs(root, testAdapters())
	assert.Empty(t, dirs["ruby"], "build dir must be skipped")
}

// TestDiscover_IgnoredDirs_DotPrefix verifies that dot-prefixed dirs are skipped.
func TestDiscover_IgnoredDirs_DotPrefix(t *testing.T) {
	root := t.TempDir()
	evil := mkdirAll(t, root, ".hidden/sub")
	touch(t, evil, "composer.lock")

	dirs, _ := discoverLaneAProjectDirs(root, testAdapters())
	assert.Empty(t, dirs["php"], "dot-prefixed dirs must be skipped")
}

// TestDiscover_IgnoredDirs_Target verifies that target (Java build output) is skipped.
func TestDiscover_IgnoredDirs_Target(t *testing.T) {
	root := t.TempDir()
	evil := mkdirAll(t, root, "target/classes")
	touch(t, evil, "composer.lock")

	dirs, _ := discoverLaneAProjectDirs(root, testAdapters())
	assert.Empty(t, dirs["php"], "target dir must be skipped")
}

// TestDiscover_IgnoredDirs_CaseInsensitive verifies that ignore-list matching is
// case-insensitive (e.g. "Vendor" is treated the same as "vendor").
func TestDiscover_IgnoredDirs_CaseInsensitive(t *testing.T) {
	root := t.TempDir()
	evil := mkdirAll(t, root, "Vendor/pkg")
	touch(t, evil, "composer.lock")

	dirs, _ := discoverLaneAProjectDirs(root, testAdapters())
	assert.Empty(t, dirs["php"], "Vendor (capitalised) must be skipped by case-insensitive check")
}

// TestDiscover_IgnoredDirs_NotDescended verifies that a manifest placed directly
// inside an ignored dir (not a subdir of an ignored dir) is also excluded.
func TestDiscover_IgnoredDirs_NotDescended(t *testing.T) {
	root := t.TempDir()
	evil := mkdirAll(t, root, "node_modules")
	touch(t, evil, "composer.lock")

	dirs, _ := discoverLaneAProjectDirs(root, testAdapters())
	assert.Empty(t, dirs["php"], "manifest inside node_modules must be skipped")
}

// TestDiscover_ValidSubdirNotIgnored verifies that a non-ignored subdir with a
// manifest IS discovered (sanity check that ignore-list doesn't over-reject).
func TestDiscover_ValidSubdirNotIgnored(t *testing.T) {
	root := t.TempDir()
	good := mkdirAll(t, root, "packages/api")
	touch(t, good, "Gemfile.lock")

	dirs, _ := discoverLaneAProjectDirs(root, testAdapters())
	assert.Equal(t, []string{good}, dirs["ruby"])
}

// TestDiscover_DepthCap verifies that a directory at depth > discoveryMaxDepth
// is NOT discovered.
func TestDiscover_DepthCap(t *testing.T) {
	root := t.TempDir()

	// Build a path exactly at max depth (should be found)
	atMax := root
	for i := 0; i < discoveryMaxDepth; i++ {
		atMax = mkdirAll(t, atMax, fmt.Sprintf("level%d", i+1))
	}
	touch(t, atMax, "composer.lock")

	// One level beyond max depth (should NOT be found)
	beyondMax := mkdirAll(t, atMax, "toodeep")
	touch(t, beyondMax, "Gemfile.lock")

	dirs, capped := discoverLaneAProjectDirs(root, testAdapters())
	assert.False(t, capped, "depth cap does not set capped=true, only project cap does")
	assert.Contains(t, dirs["php"], atMax, "dir at max depth must be discovered")
	assert.Empty(t, dirs["ruby"], "dir beyond max depth must NOT be discovered")
}

// TestDiscover_ProjectDirCap verifies that when the total matching directories
// exceeds discoveryMaxDirs, the walk stops and capped=true is returned.
func TestDiscover_ProjectDirCap(t *testing.T) {
	root := t.TempDir()

	// Create discoveryMaxDirs+1 matching subdirectories.
	total := discoveryMaxDirs + 1
	for i := 0; i < total; i++ {
		sub := mkdirAll(t, root, fmt.Sprintf("proj%04d", i))
		touch(t, sub, "composer.lock")
	}

	dirs, capped := discoverLaneAProjectDirs(root, testAdapters())
	assert.True(t, capped, "capped must be true when project dir count exceeds cap")
	// We expect at most discoveryMaxDirs entries across all adapters.
	assert.LessOrEqual(t, len(dirs["php"]), discoveryMaxDirs,
		"php dirs must not exceed cap")
}

// TestDiscover_GlobDetectFile verifies that suffix-glob DetectFiles (e.g. "*.csproj")
// are matched correctly in subdirectories.
func TestDiscover_GlobDetectFile(t *testing.T) {
	root := t.TempDir()
	sub := mkdirAll(t, root, "MyProject")
	touch(t, sub, "MyProject.csproj") // matches "*.csproj" glob

	dirs, capped := discoverLaneAProjectDirs(root, testAdaptersWithGlob())
	assert.False(t, capped)
	assert.Equal(t, []string{sub}, dirs["dotnet"])
}

// TestDiscover_ExactFileNotGlob verifies that an exact DetectFile name is matched
// (not confused with a glob).
func TestDiscover_ExactFileNotGlob(t *testing.T) {
	root := t.TempDir()
	sub := mkdirAll(t, root, "app")
	touch(t, sub, "packages.lock.json")

	dirs, capped := discoverLaneAProjectDirs(root, testAdaptersWithGlob())
	assert.False(t, capped)
	assert.Equal(t, []string{sub}, dirs["dotnet"])
}

// TestDiscover_NoAdapters verifies that zero adapters returns an empty map.
func TestDiscover_NoAdapters(t *testing.T) {
	root := t.TempDir()
	touch(t, root, "composer.lock")

	dirs, capped := discoverLaneAProjectDirs(root, nil)
	assert.False(t, capped)
	assert.Empty(t, dirs)
}

// TestDiscover_IgnoredDirs_AllListed verifies that every directory in the
// ignoredDirSet is actually skipped.
func TestDiscover_IgnoredDirs_AllListed(t *testing.T) {
	adapters := testAdapters()
	for name := range ignoredDirSet {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			evil := mkdirAll(t, root, name)
			touch(t, evil, "composer.lock")

			dirs, _ := discoverLaneAProjectDirs(root, adapters)
			assert.Empty(t, dirs["php"],
				"manifest inside %q must be skipped by ignore-list", name)
		})
	}
}

// TestDiscover_RootIsAlwaysChecked verifies that the root directory itself is
// never skipped even though its name might not be special.
func TestDiscover_RootIsAlwaysChecked(t *testing.T) {
	root := t.TempDir()
	touch(t, root, "Gemfile.lock")

	dirs, _ := discoverLaneAProjectDirs(root, testAdapters())
	assert.Equal(t, []string{root}, dirs["ruby"])
}
