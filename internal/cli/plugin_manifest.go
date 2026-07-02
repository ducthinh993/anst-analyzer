package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/commit0-dev/commit0-analyzer/internal/advisory"
	"github.com/commit0-dev/commit0-analyzer/internal/host"
	commit0v1 "github.com/commit0-dev/commit0-analyzer/pkg/contract/commit0v1"
)

// This file holds the data-driven plugin-dispatch seam for graduated
// (HasPlugin) lockfile ecosystems. It generalizes the per-language
// buildRustPluginManifest/buildPythonPluginManifest builders into one builder
// keyed off the EcosystemAdapter, so each new ecosystem phase adds only its own
// plugin dir + ecosystem_<name>.go and never edits scan.go or the registry.

// lockfileDistDir returns the absolute path to a graduated adapter's plugin dist
// directory (plugins/<baseName>-reachability/dist), resolved relative to this
// source file's repository location for dev/test and falling back to a path
// adjacent to the running executable for an installed build. Returns "" only
// when the executable path cannot be resolved.
func lockfileDistDir(baseName string) string {
	// Prefer the repo-relative path for development and test.
	_, thisFile, _, ok := runtime.Caller(0)
	if ok {
		// This file is at internal/cli/plugin_manifest.go; repo root is two dirs up.
		repoRoot := filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
		candidate := filepath.Join(repoRoot, "plugins", baseName+"-reachability", "dist")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	// Fall back to a path adjacent to the running executable (installed build).
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Join(filepath.Dir(exe), "plugins", baseName+"-reachability", "dist")
}

// buildLockfilePluginManifest constructs a host.Manifest for a graduated
// adapter's reachability plugin, mirroring buildRustPluginManifest /
// buildPythonPluginManifest: it locates (or on-demand `go build`s) the plugin's
// single-binary distribution and computes a SHA-256 pin.
//
// The plugin lives at plugins/<base>-reachability/, builds to the binary
// commit0-<base>-reachability, and registers under the manifest name
// <base>-reachability, where base is adapter.pluginBaseName().
//
// When overrideBin is non-empty it is used directly (build disabled). When
// overrideBin is empty and the dist binary is absent, it is built on demand.
// Returns (manifest, true) on success, or (nil, false) when the build fails or
// the binary cannot be located — callers MUST treat (nil, false) as "plugin
// absent" and degrade to the direct lockfile PACKAGE_REACHABLE path (never a
// silent skip).
func buildLockfilePluginManifest(ctx context.Context, adapter EcosystemAdapter, overrideBin string) (*host.Manifest, bool) {
	baseName := adapter.pluginBaseName()
	manifestName := baseName + "-reachability"

	var mainBin string
	if overrideBin != "" {
		mainBin = overrideBin
	} else {
		distDir := lockfileDistDir(baseName)
		if distDir == "" {
			return nil, false
		}
		mainBin = filepath.Join(distDir, "commit0-"+manifestName)

		// On-demand build: if the dist binary is absent, build it now.
		if _, err := os.Stat(mainBin); err != nil {
			pluginPkg := "github.com/commit0-dev/commit0-analyzer/plugins/" + manifestName
			if mkErr := os.MkdirAll(distDir, 0o755); mkErr != nil {
				fmt.Fprintf(os.Stderr,
					"warning: cannot create %s plugin dist dir %s: %v; %s reachability plugin unavailable\n",
					baseName, distDir, mkErr, adapter.Language)
				return nil, false
			}
			cmd := exec.CommandContext(ctx, "go", "build", "-o", mainBin, pluginPkg)
			cmd.Env = os.Environ()
			if out, buildErr := cmd.CombinedOutput(); buildErr != nil {
				fmt.Fprintf(os.Stderr,
					"warning: on-demand build of %s plugin failed: %v\n%s; %s reachability plugin unavailable\n",
					baseName, buildErr, out, adapter.Language)
				return nil, false
			}
		}
	}

	if _, err := os.Stat(mainBin); err != nil {
		// Binary not present even after build attempt: graceful skip.
		return nil, false
	}

	absMain, err := filepath.Abs(mainBin)
	if err != nil {
		return nil, false
	}

	hash, err := host.SHA256OfFile(absMain)
	if err != nil {
		return nil, false
	}

	return &host.Manifest{
		Name:      manifestName,
		ExecPath:  absMain,
		Pillar:    "sca",
		Languages: []string{adapter.Language},
		SHA256:    hash,
	}, true
}

// suppressDirectLockfileFinding reports whether the host should skip generating
// the direct lockfile PACKAGE_REACHABLE finding for an adapter, deferring
// instead to its reachability plugin.
//
// It suppresses ONLY when the adapter has graduated (HasPlugin) AND its plugin
// will actually run (pluginWillRun). When a graduated adapter's plugin is
// absent or failed to build, pluginWillRun is false and the direct finding is
// kept — the fallback path, byte-identical to the pre-graduation behavior. This
// is the guard against a silent skip (losing advisory coverage) when a plugin
// cannot run.
func suppressDirectLockfileFinding(adapter EcosystemAdapter, pluginWillRun bool) bool {
	return adapter.HasPlugin && pluginWillRun
}

// newDirectLockfileFinding builds the host-generated PACKAGE_REACHABLE (or
// UNKNOWN, when the advisory match is undecidable) finding for a lockfile-static
// ecosystem. This is the finding emitted when no reachability plugin runs for
// the ecosystem; extracting it guarantees the fallback path stays identical
// whether or not the adapter has graduated.
func newDirectLockfileFinding(adapter EcosystemAdapter, dep advisoryDep, adv *advisory.Advisory) *commit0v1.Finding {
	conf := ceilingToConfidence(adapter.MaxConfidence)
	if adv.Incomplete {
		conf = commit0v1.Confidence_CONFIDENCE_UNKNOWN
	}
	return &commit0v1.Finding{
		Advisory: &commit0v1.AdvisoryRef{
			Id:      adv.ID,
			Aliases: append([]string(nil), adv.Aliases...),
		},
		Module:     dep.Module,
		Confidence: conf,
		Incomplete: adv.Incomplete,
		Pillar:     "sca",
		Language:   adapter.Language,
	}
}

// resolvedDepsForAdapter maps the host's deduped lockfile closure into the
// wire-level resolved_deps a graduated plugin consumes (so the plugin never
// re-parses the lockfile in its own language).
func resolvedDepsForAdapter(adapter EcosystemAdapter, deps []ResolvedDep) []*commit0v1.ResolvedDependency {
	if len(deps) == 0 {
		return nil
	}
	eco := protoEcosystem(adapter.Ecosystem)
	out := make([]*commit0v1.ResolvedDependency, 0, len(deps))
	for _, d := range deps {
		out = append(out, &commit0v1.ResolvedDependency{
			Name:      d.Name,
			Version:   d.Version,
			DepType:   d.DepType,
			Ecosystem: eco,
		})
	}
	return out
}

// protoEcosystem maps an advisory ecosystem tag to its wire-level Ecosystem
// enum. Ecosystems without a dedicated enum value yet (their proto value is
// added additively in their own phase) map to ECOSYSTEM_UNKNOWN; a
// single-ecosystem plugin does not depend on this discriminator.
func protoEcosystem(name string) commit0v1.Ecosystem {
	switch name {
	case advisory.EcosystemGo:
		return commit0v1.Ecosystem_ECOSYSTEM_GO
	case advisory.EcosystemNPM:
		return commit0v1.Ecosystem_ECOSYSTEM_NPM
	case advisory.EcosystemCratesIO:
		return commit0v1.Ecosystem_ECOSYSTEM_CRATES_IO
	case advisory.EcosystemPyPI:
		return commit0v1.Ecosystem_ECOSYSTEM_PYPI
	case advisory.EcosystemMaven:
		return commit0v1.Ecosystem_ECOSYSTEM_MAVEN
	default:
		return commit0v1.Ecosystem_ECOSYSTEM_UNKNOWN
	}
}
