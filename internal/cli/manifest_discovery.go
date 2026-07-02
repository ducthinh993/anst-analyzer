package cli

// manifest_discovery.go — bounded directory walk to locate Lane-A manifest files
// in multi-project (subdirectory) layouts.
//
// Design contract:
//   - Walk depth is bounded to discoveryMaxDepth levels below moduleRoot.
//   - Ignored directories (ignoredDirSet) are pruned with fs.SkipDir so the
//     walk never descends into dependency/build/VCS trees.
//   - Any directory whose name begins with "." is also pruned.
//   - At most discoveryMaxDirs unique matching directories are collected across
//     all adapters. If the cap is reached, the walk terminates early and
//     capped=true is returned. Callers MUST propagate capped → incomplete=true
//     (unknown ≠ safe: a silently truncated discovery must not read as complete).

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const (
	// discoveryMaxDepth is the maximum number of directory levels to descend
	// below moduleRoot. A directory at this depth is scanned; its children are not.
	discoveryMaxDepth = 5

	// discoveryMaxDirs is the maximum total number of unique matching project
	// directories collected across all adapters in a single discovery run.
	// When reached the walk stops early and capped=true is returned.
	discoveryMaxDirs = 100
)

// ignoredDirSet lists directory names that are never descended during discovery.
// Lookup is case-insensitive (names are lower-cased before lookup).
// Additionally, any directory name starting with "." is always pruned.
var ignoredDirSet = map[string]struct{}{
	".git":        {},
	"node_modules": {},
	"vendor":      {},
	"dist":        {},
	"build":       {},
	"target":      {},
	"out":         {},
	"bin":         {},
	"obj":         {},
	".gradle":     {},
	".build":      {},
	"pods":        {}, // Pods (CocoaPods)
	"carthage":    {}, // Carthage
	"testdata":    {},
	".venv":       {},
	"venv":        {},
	"__pycache__": {},
	".terraform":  {},
	".idea":       {},
	".vscode":     {},
}

// dirMatchesAdapter reports whether dir contains at least one of the adapter's
// DetectFiles. DetectFiles entries starting with "*." are treated as suffix globs
// (e.g. "*.csproj" matches any non-directory file whose name ends in ".csproj").
// All other entries are matched as exact filenames.
func dirMatchesAdapter(dir string, a EcosystemAdapter) bool {
	for _, f := range a.DetectFiles {
		if strings.HasPrefix(f, "*.") {
			suffix := strings.ToLower(f[1:]) // e.g. "*.csproj" → ".csproj"
			entries, err := os.ReadDir(dir)
			if err != nil {
				continue
			}
			for _, entry := range entries {
				if !entry.IsDir() && strings.HasSuffix(strings.ToLower(entry.Name()), suffix) {
					return true
				}
			}
		} else {
			if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
				return true
			}
		}
	}
	return false
}

// ensureRootFirst returns dirs with moduleRoot prepended if it is not already
// present. Used by the Lane-A scan loop to ensure the root directory is always
// scanned when an adapter is active via root detection or an explicit --language
// flag, even if discovery did not find a manifest there.
func ensureRootFirst(dirs []string, moduleRoot string) []string {
	for _, d := range dirs {
		if d == moduleRoot {
			return dirs
		}
	}
	out := make([]string, 0, len(dirs)+1)
	out = append(out, moduleRoot)
	out = append(out, dirs...)
	return out
}

// dedupLaneADeps deduplicates a slice of ResolvedDep by normalised name@version,
// preserving first-seen order. When the same package appears in multiple
// sub-projects with different DepTypes, the result carries the most conservative
// type: "runtime" beats any other value (matching mergeDepType semantics so that
// a package that is runtime in one sub-project is never accidentally downgraded
// to "dev" by another sub-project's annotation).
//
// normalize may be nil, in which case dep.Name is used as-is.
func dedupLaneADeps(deps []ResolvedDep, normalize func(string) string) []ResolvedDep {
	type key struct{ name, version string }
	type entry struct {
		dep     ResolvedDep
		depType string // merged depType for this key
	}

	seen := make(map[key]*entry, len(deps))
	order := make([]key, 0, len(deps))

	for _, dep := range deps {
		n := dep.Name
		if normalize != nil {
			n = normalize(n)
		}
		k := key{n, dep.Version}

		dt := dep.DepType
		if dt == "" {
			dt = "runtime" // unknown ≠ safe: default to runtime
		}

		if e, exists := seen[k]; !exists {
			d := dep
			d.Name = n
			d.DepType = dt
			seen[k] = &entry{dep: d, depType: dt}
			order = append(order, k)
		} else if e.depType != "runtime" {
			if dt == "runtime" {
				e.depType = "runtime" // runtime wins
			}
			// other non-runtime: keep the first-seen type
		}
	}

	out := make([]ResolvedDep, 0, len(order))
	for _, k := range order {
		e := seen[k]
		e.dep.DepType = e.depType
		out = append(out, e.dep)
	}
	return out
}

// discoverLaneAProjectDirs walks moduleRoot (up to discoveryMaxDepth levels deep)
// and returns, for each Lane-A adapter Language, the set of directories that
// contain at least one of that adapter's DetectFiles.
//
// Walk properties:
//   - moduleRoot is always checked first and included in the result if it matches.
//   - Directories in ignoredDirSet (case-insensitive) and any directory whose
//     name begins with "." are pruned with fs.SkipDir (never descended).
//   - Directories deeper than discoveryMaxDepth are pruned with fs.SkipDir.
//   - At most discoveryMaxDirs unique project directories are collected across all
//     adapters. If the cap is reached the walk terminates with capped=true.
//
// Callers MUST set incomplete=true when capped=true.
func discoverLaneAProjectDirs(moduleRoot string, adapters []EcosystemAdapter) (dirs map[string][]string, capped bool) {
	dirs = make(map[string][]string)
	if len(adapters) == 0 {
		return
	}

	// seenDirs tracks unique directories that matched at least one adapter.
	// Used to count toward the project-dir cap.
	seenDirs := make(map[string]bool)

	_ = filepath.WalkDir(moduleRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Skip unreadable entries without failing the entire walk.
			return nil
		}
		if !d.IsDir() {
			return nil
		}

		// Compute depth relative to moduleRoot.
		rel, relErr := filepath.Rel(moduleRoot, path)
		if relErr != nil {
			return nil
		}
		depth := 0
		if rel != "." {
			depth = strings.Count(rel, string(filepath.Separator)) + 1
		}

		// Prune directories beyond the depth cap.
		if depth > discoveryMaxDepth {
			return fs.SkipDir
		}

		// Prune ignored directories (non-root only; root is always checked).
		if path != moduleRoot {
			name := d.Name()
			if strings.HasPrefix(name, ".") {
				return fs.SkipDir
			}
			if _, skip := ignoredDirSet[strings.ToLower(name)]; skip {
				return fs.SkipDir
			}
		}

		// Check which adapters match this directory.
		matched := false
		for _, a := range adapters {
			if dirMatchesAdapter(path, a) {
				dirs[a.Language] = append(dirs[a.Language], path)
				matched = true
			}
		}

		// Count unique matching directories toward the cap.
		if matched && !seenDirs[path] {
			seenDirs[path] = true
			if len(seenDirs) >= discoveryMaxDirs {
				capped = true
				return fs.SkipAll
			}
		}

		return nil
	})

	return
}
