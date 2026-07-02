package lockfilekit

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// wordParse is a trivial token extractor: it splits on non-letters. It always
// succeeds, so it isolates walk behavior from parse behavior.
func wordParse(_ string, content []byte) ([]string, bool) {
	return strings.FieldsFunc(string(content), nonLetter), true
}

// nonLetter reports whether r is not an ASCII letter (a token separator).
func nonLetter(r rune) bool {
	return (r < 'a' || r > 'z') && (r < 'A' || r > 'Z')
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
}

func TestWalk_CollectsTokensFromMatchingFiles(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a.dart"), "import foo bar")
	writeFile(t, filepath.Join(root, "sub", "b.dart"), "baz")
	writeFile(t, filepath.Join(root, "c.txt"), "ignored") // non-matching extension

	used, incomplete, err := Walk(root, WalkConfig{Extensions: []string{".dart"}, Parse: wordParse})
	require.NoError(t, err)
	assert.False(t, incomplete)
	assert.True(t, used.Has("foo"))
	assert.True(t, used.Has("bar"))
	assert.True(t, used.Has("baz"))
	assert.False(t, used.Has("ignored"), "non-matching extensions must not be parsed")
}

func TestWalk_ParseFailureSetsIncomplete(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "ok.dart"), "alpha")
	writeFile(t, filepath.Join(root, "bad.dart"), "beta")

	parse := func(path string, content []byte) ([]string, bool) {
		if strings.HasSuffix(path, "bad.dart") {
			return nil, false // simulate a parse error
		}
		return wordParse(path, content)
	}

	used, incomplete, err := Walk(root, WalkConfig{Extensions: []string{".dart"}, Parse: parse})
	require.NoError(t, err)
	assert.True(t, incomplete, "a single parse failure must set parseIncomplete (forbids NOT_REACHABLE)")
	assert.True(t, used.Has("alpha"), "tokens from files that parsed are still collected")
}

func TestWalk_IgnoresVendorAndHiddenDirs(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "main.dart"), "kept")
	writeFile(t, filepath.Join(root, "vendor", "dep.dart"), "vendored")
	writeFile(t, filepath.Join(root, ".idea", "conf.dart"), "hidden")

	used, incomplete, err := Walk(root, WalkConfig{Extensions: []string{".dart"}, Parse: wordParse})
	require.NoError(t, err)
	assert.False(t, incomplete)
	assert.True(t, used.Has("kept"))
	assert.False(t, used.Has("vendored"), "vendor/ must be skipped (not project source)")
	assert.False(t, used.Has("hidden"), "hidden dirs must be skipped")
}

func TestWalk_MaxFilesCapSetsIncomplete(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a.dart"), "one")
	writeFile(t, filepath.Join(root, "b.dart"), "two")
	writeFile(t, filepath.Join(root, "c.dart"), "three")

	_, incomplete, err := Walk(root, WalkConfig{Extensions: []string{".dart"}, MaxFiles: 1, Parse: wordParse})
	require.NoError(t, err)
	assert.True(t, incomplete, "hitting the MaxFiles cap means unseen source → incomplete")
}

func TestWalk_OversizeFileSetsIncomplete(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "big.dart"), strings.Repeat("x", 100))

	_, incomplete, err := Walk(root, WalkConfig{Extensions: []string{".dart"}, MaxFileBytes: 10, Parse: wordParse})
	require.NoError(t, err)
	assert.True(t, incomplete, "an unread oversize file must set incomplete, never be silently skipped")
}

func TestWalk_DoesNotFollowSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is unreliable on Windows CI")
	}
	root := t.TempDir()
	outside := t.TempDir()
	writeFile(t, filepath.Join(outside, "escaped.dart"), "escaped")
	writeFile(t, filepath.Join(root, "in.dart"), "inside")

	// A symlink pointing outside the project root must not be followed.
	require.NoError(t, os.Symlink(outside, filepath.Join(root, "link")))

	used, _, err := Walk(root, WalkConfig{Extensions: []string{".dart"}, Parse: wordParse})
	require.NoError(t, err)
	assert.True(t, used.Has("inside"))
	assert.False(t, used.Has("escaped"), "symlinks must never be followed (could escape root)")
}
