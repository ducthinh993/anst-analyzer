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

// loadPackageConfig parses .dart_tool/package_config.json and returns a map from
// package name to its importable source directory (rootUri joined with
// packageUri, i.e. where `package:NAME/...` resolves).
//
// The bool is false when the file is absent or cannot be parsed. In that case the
// transitive used-import closure CANNOT be completed — the caller MUST treat the
// closure as incomplete and forbid NOT_REACHABLE. This is the sound response to a
// project that has not run `dart pub get`; the plugin never runs it itself
// (running it would execute build hooks — arbitrary code execution).
func loadPackageConfig(dartToolDir string) (map[string]string, bool) {
	data, err := os.ReadFile(filepath.Join(dartToolDir, "package_config.json"))
	if err != nil {
		return nil, false
	}
	var raw rawPackageConfig
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, false
	}
	out := make(map[string]string, len(raw.Packages))
	for _, p := range raw.Packages {
		if p.Name == "" {
			continue
		}
		out[p.Name] = resolvePackageDir(dartToolDir, p.RootURI, p.PackageURI)
	}
	return out, true
}

// resolvePackageDir maps a package_config.json entry to a local directory.
//
// rootUri is either an absolute file:// URI or a path relative to the directory
// holding package_config.json (i.e. .dart_tool/). packageUri (default "lib/") is
// the subdirectory under rootUri where `package:NAME/...` imports resolve.
func resolvePackageDir(dartToolDir, rootURI, packageURI string) string {
	if packageURI == "" {
		packageURI = "lib/"
	}
	base := dartToolDir
	if u, err := url.Parse(rootURI); err == nil && u.Scheme == "file" {
		base = filepath.FromSlash(u.Path)
	} else if rootURI != "" {
		base = filepath.Join(dartToolDir, filepath.FromSlash(rootURI))
	}
	return filepath.Join(base, filepath.FromSlash(packageURI))
}
