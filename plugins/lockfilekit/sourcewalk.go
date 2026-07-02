package lockfilekit

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// defaultIgnoreDirs are directory names never descended into during a source
// walk: version-control metadata, dependency caches, and build outputs. A
// package's own vendored copy under one of these is not project source.
var defaultIgnoreDirs = map[string]struct{}{
	".git": {}, ".hg": {}, ".svn": {},
	"node_modules": {}, "vendor": {}, ".dart_tool": {},
	"build": {}, "dist": {}, "out": {}, "target": {},
	".venv": {}, "venv": {}, "__pycache__": {},
}

// WalkConfig configures a bounded, parse-complete project source walk.
type WalkConfig struct {
	// Extensions is the set of file suffixes to parse (e.g. []string{".dart"}).
	// A file whose name ends with any entry is passed to Parse. Empty means "no
	// files match" (the walk yields an empty token set, not an error).
	Extensions []string

	// IgnoreDirs are additional directory names to skip beyond defaultIgnoreDirs.
	IgnoreDirs []string

	// MaxFiles caps the number of source files parsed. When exceeded the walk
	// stops and reports parseIncomplete=true (the unseen files could reference a
	// package, so the closure of used tokens is not proven complete). Zero means
	// no cap.
	MaxFiles int

	// MaxFileBytes caps a single file's size. A larger file is not read; it is
	// treated as a parse failure (parseIncomplete=true) rather than silently
	// skipped. Zero means no cap.
	MaxFileBytes int64

	// Parse extracts the referenced identifiers from one source file. It returns
	// (tokens, ok); ok=false marks the file as failing to parse, which forbids
	// NOT_REACHABLE for the whole project ("unknown ≠ safe"). Parse MUST be pure
	// and side-effect-free — it never executes the source.
	Parse func(path string, content []byte) (tokens []string, ok bool)
}

// Walk traverses root, parsing every file that matches WalkConfig.Extensions and
// unioning the tokens each Parse returns. It is symlink-safe (symlinks are never
// followed — a symlink could escape the project root or point at an attacker
// artifact) and respects the ignore list.
//
// It returns (used, parseIncomplete, err). parseIncomplete is true when ANY file
// failed to parse, exceeded MaxFileBytes, could not be read, or the MaxFiles cap
// was hit — any of which means the used-token set may be missing a reference, so
// the caller MUST NOT emit NOT_REACHABLE. err is non-nil only for a walk-level
// failure (e.g. root unreadable); per-file problems set parseIncomplete instead.
func Walk(root string, cfg WalkConfig) (used Set, parseIncomplete bool, err error) {
	used = make(Set)
	ignore := make(map[string]struct{}, len(defaultIgnoreDirs)+len(cfg.IgnoreDirs))
	for d := range defaultIgnoreDirs {
		ignore[d] = struct{}{}
	}
	for _, d := range cfg.IgnoreDirs {
		ignore[d] = struct{}{}
	}

	fileCount := 0
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			// A directory we cannot read means unseen source: degrade, don't fail.
			parseIncomplete = true
			return nil //nolint:nilerr // partial walk → incomplete, never a false clean
		}

		// Never follow symlinks: a symlink may escape root or point at a
		// package artifact, neither of which is project source under our control.
		if d.Type()&fs.ModeSymlink != 0 {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		if d.IsDir() {
			if path != root {
				if _, skip := ignore[d.Name()]; skip {
					return fs.SkipDir
				}
				// Skip hidden directories (e.g. ".idea"); project source lives in
				// visible trees. The root itself is always descended.
				if strings.HasPrefix(d.Name(), ".") {
					return fs.SkipDir
				}
			}
			return nil
		}

		if !matchesExtension(d.Name(), cfg.Extensions) {
			return nil
		}

		if cfg.MaxFiles > 0 && fileCount >= cfg.MaxFiles {
			parseIncomplete = true
			return filepath.SkipAll
		}
		fileCount++

		if cfg.MaxFileBytes > 0 {
			if info, statErr := d.Info(); statErr == nil && info.Size() > cfg.MaxFileBytes {
				parseIncomplete = true
				return nil
			}
		}

		content, readErr := os.ReadFile(path)
		if readErr != nil {
			parseIncomplete = true
			return nil
		}

		tokens, ok := cfg.Parse(path, content)
		if !ok {
			parseIncomplete = true
			return nil
		}
		for _, tok := range tokens {
			used.Add(tok)
		}
		return nil
	})
	if walkErr != nil {
		return used, parseIncomplete, walkErr
	}
	return used, parseIncomplete, nil
}

// matchesExtension reports whether name ends with any of the extensions.
func matchesExtension(name string, exts []string) bool {
	for _, ext := range exts {
		if strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}
