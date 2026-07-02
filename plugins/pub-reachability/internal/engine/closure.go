package engine

import (
	"os"
	"path/filepath"

	"github.com/commit0-dev/commit0-analyzer/plugins/lockfilekit"
	"github.com/commit0-dev/commit0-analyzer/plugins/pub-reachability/internal/dartimports"
)

const (
	// maxDartFileBytes caps a single source file. A larger file is not read and
	// marks the scan incomplete (unknown ≠ safe) rather than being skipped.
	maxDartFileBytes = 8 << 20 // 8 MiB
	// maxDartFiles bounds a single directory walk so a pathological tree cannot
	// exceed the runtime budget; hitting the cap marks the scan incomplete.
	maxDartFiles = 50000
)

// closure is the project's transitive used-import closure plus the soundness
// flags that gate NOT_REACHABLE.
type closure struct {
	// Used is every package name reachable through the static import/export graph
	// starting from project source (direct imports and imports of used packages).
	Used lockfilekit.Set

	// Frontier holds the dynamism markers found anywhere in the walked source. A
	// non-empty frontier forbids NOT_REACHABLE for the whole project.
	Frontier lockfilekit.Frontier

	// ParseIncomplete is true when a source file failed to parse, was too large,
	// or referenced an absent part file — the used set may miss a reference.
	ParseIncomplete bool

	// TransitiveIncomplete is true when package_config.json was absent or a used
	// package's source directory could not be located/walked, so the transitive
	// closure is not proven complete.
	TransitiveIncomplete bool
}

// Size reports the number of packages in the used-import closure (evidence for a
// NOT_REACHABLE finding).
func (c closure) Size() int { return len(c.Used) }

// buildClosure computes the transitive used-import closure for a project root.
//
// It starts from every package the project's own source imports, then walks each
// used package's importable source (resolved via .dart_tool/package_config.json)
// to discover the packages IT imports, iterating to a fixed point. A transitive
// dependency that the project reaches only through another package is therefore
// counted as used — the guard against a false NOT_REACHABLE for a package that is
// referenced only indirectly.
func buildClosure(root string) closure {
	frontier := &lockfilekit.Frontier{}

	// A build hook can synthesize imports that never appear in static source.
	if fileExists(filepath.Join(root, "build.dart")) ||
		fileExists(filepath.Join(root, "hook", "build.dart")) {
		frontier.Add("build.dart build hook may synthesize imports")
	}

	roots, parseIncomplete := scanDir(root, frontier)
	used := lockfilekit.NewSet()
	for tok := range roots {
		used.Add(tok)
	}

	pc, ok := loadPackageConfig(filepath.Join(root, ".dart_tool"))
	transitiveIncomplete := !ok
	if ok {
		visited := lockfilekit.NewSet()
		queue := make([]string, 0, len(roots))
		for tok := range roots {
			queue = append(queue, tok)
		}
		for len(queue) > 0 {
			pkg := queue[0]
			queue = queue[1:]
			if visited.Has(pkg) {
				continue
			}
			visited.Add(pkg)

			dir, found := pc[pkg]
			if !found || !dirExists(dir) {
				// A used package whose source we cannot locate/read means the
				// transitive walk is not proven complete → no NOT_REACHABLE.
				transitiveIncomplete = true
				continue
			}
			tokens, inc := scanDir(dir, frontier)
			if inc {
				parseIncomplete = true
			}
			for tk := range tokens {
				used.Add(tk)
				if !visited.Has(tk) {
					queue = append(queue, tk)
				}
			}
		}
	}

	return closure{
		Used:                 used,
		Frontier:             *frontier,
		ParseIncomplete:      parseIncomplete,
		TransitiveIncomplete: transitiveIncomplete,
	}
}

// scanDir walks every .dart file under dir, unioning the package tokens each
// imports and folding any dynamism markers into frontier. The bool reports parse
// incompleteness (a file failed to lex, was oversize, hit the file cap, or
// referenced an absent part file).
func scanDir(dir string, frontier *lockfilekit.Frontier) (lockfilekit.Set, bool) {
	used, incomplete, err := lockfilekit.Walk(dir, lockfilekit.WalkConfig{
		Extensions:   []string{".dart"},
		MaxFiles:     maxDartFiles,
		MaxFileBytes: maxDartFileBytes,
		Parse: func(path string, content []byte) ([]string, bool) {
			s := dartimports.ScanSource(content)
			if s.MirrorsImport {
				frontier.Add("dart:mirrors reflection import")
			}
			if s.SpawnUri {
				frontier.Add("Isolate.spawnUri dynamic code load")
			}
			ok := true
			for _, pf := range s.PartFiles {
				partPath := filepath.Join(filepath.Dir(path), filepath.FromSlash(pf))
				if !fileExists(partPath) {
					// A referenced part file absent from the tree (e.g. a generated
					// *.g.dart that codegen has not produced) hides source that could
					// import a package → mark incomplete, forbidding NOT_REACHABLE.
					ok = false
				}
			}
			return s.ImportPackages, ok
		},
	})
	if err != nil {
		incomplete = true
	}
	return used, incomplete
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

func dirExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.IsDir()
}
