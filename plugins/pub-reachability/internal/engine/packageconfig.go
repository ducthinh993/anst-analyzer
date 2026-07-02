package engine

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
)

// rawPackageConfig is the on-disk shape of .dart_tool/package_config.json (the
// v2 file `dart pub get` writes). Only the fields needed to resolve a package
// name to its importable source directory are modeled.
type rawPackageConfig struct {
	Packages []struct {
		Name       string `json:"name"`
		RootURI    string `json:"rootUri"`
		PackageURI string `json:"packageUri"`
	} `json:"packages"`
}

// pkgLocation is where one package lives on disk.
type pkgLocation struct {
	// Root is the package's root directory (rootUri) — where its pubspec and any
	// build hook (build.dart, hook/build.dart) live.
	Root string
	// Source is the importable source directory (rootUri joined with packageUri,
	// default lib/) — where `package:NAME/...` imports resolve.
	Source string
}

// loadPackageConfig parses .dart_tool/package_config.json and returns a map from
// package name to its on-disk location (root + importable source dir).
//
// The bool is false when the file is absent or cannot be parsed. In that case the
// transitive used-import closure CANNOT be completed — the caller MUST treat the
// closure as incomplete and forbid NOT_REACHABLE. This is the sound response to a
// project that has not run `dart pub get`; the plugin never runs it itself
// (running it would execute build hooks — arbitrary code execution).
func loadPackageConfig(dartToolDir string) (map[string]pkgLocation, bool) {
	data, err := os.ReadFile(filepath.Join(dartToolDir, "package_config.json"))
	if err != nil {
		return nil, false
	}
	var raw rawPackageConfig
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, false
	}
	out := make(map[string]pkgLocation, len(raw.Packages))
	for _, p := range raw.Packages {
		if p.Name == "" {
			continue
		}
		root := resolvePackageRoot(dartToolDir, p.RootURI)
		out[p.Name] = pkgLocation{Root: root, Source: resolveSourceDir(root, p.PackageURI)}
	}
	return out, true
}

// resolvePackageRoot maps a package_config.json rootUri to a local directory.
// rootUri is either an absolute file:// URI or a path relative to the directory
// holding package_config.json (i.e. .dart_tool/).
func resolvePackageRoot(dartToolDir, rootURI string) string {
	if u, err := url.Parse(rootURI); err == nil && u.Scheme == "file" {
		return filepath.FromSlash(u.Path)
	}
	if rootURI != "" {
		return filepath.Join(dartToolDir, filepath.FromSlash(rootURI))
	}
	return dartToolDir
}

// resolveSourceDir joins a package root with its packageUri (default "lib/"),
// yielding the directory where `package:NAME/...` imports resolve.
func resolveSourceDir(root, packageURI string) string {
	if packageURI == "" {
		packageURI = "lib/"
	}
	return filepath.Join(root, filepath.FromSlash(packageURI))
}
