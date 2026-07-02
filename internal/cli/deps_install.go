package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// Automatic dependency installation (deepest-security default).
//
// By default `commit0-analyzer scan` materializes the scanned project's dependency
// closure before analysis so that reachability analysis sees the real installed
// graph. Users opt out with --skip-deps-install (or --offline, which never
// installs).
//
// ────────────────────────────────────────────────────────────────────────────
// SECURITY (non-negotiable): every install MUST disable lifecycle/build scripts.
// A security scanner must NEVER execute untrusted package install/postinstall
// code by default. The npm/pnpm/yarn invocations always pass a scripts-disabling
// flag (--ignore-scripts), and the Rust path uses `cargo fetch`, which only
// populates the registry cache and never runs build.rs or proc-macros. Python
// auto-install is deliberately deferred (see below) because installing sdists
// runs setup.py / build backends — a code-execution risk we will not take by
// default.
// ────────────────────────────────────────────────────────────────────────────
//
// Robustness contract: a missing package-manager binary, a failing install
// command, or offline mode degrades to a warning on stderr and CONTINUES the
// scan. The downstream model-incompleteness handling (unknown ≠ safe) marks the
// scan incomplete if deps are still missing — installation is best-effort, never
// a hard gate.

// nodeModulesDir is the npm/pnpm/yarn install target directory. Referenced via a
// const so the literal lives in exactly one place.
const nodeModulesDir = "node_modules"

// installPlan describes a single package-manager invocation chosen for an
// ecosystem. A plan with skip=true is a deliberate no-op (e.g. dependencies are
// already present); skipReason explains why.
type installPlan struct {
	pm         string   // package-manager binary, e.g. "pnpm", "yarn", "npm", "cargo"
	args       []string // arguments; always include a scripts-disabling flag for JS
	skip       bool     // true ⇒ do not run anything for this ecosystem
	skipReason string   // human-readable reason when skip is true
}

// runInstallCommand executes a planned package-manager install command in dir.
// It is a package-level var so tests can capture the chosen command + args
// without invoking a real package manager.
//
// The command's stdout is redirected to stderr so that install chatter can never
// contaminate the scan's machine-readable stdout (SARIF/JSON go to stdout).
var runInstallCommand = defaultRunInstallCommand

func defaultRunInstallCommand(ctx context.Context, dir, pm string, args []string) error {
	if _, err := exec.LookPath(pm); err != nil {
		return fmt.Errorf("%s not found on PATH: %w", pm, err)
	}
	cmd := exec.CommandContext(ctx, pm, args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stderr // keep stdout reserved for SARIF/JSON output
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// installDependencies materializes the dependency closure for every detected
// ecosystem that supports a safe (scripts-disabled) install. It never fails the
// scan: every error path warns and continues. offline short-circuits the whole
// step (no network ⇒ no install).
//
// Per-ecosystem behaviour:
//   - JS:     npm/pnpm/yarn install with lifecycle scripts disabled, frozen when
//     a lockfile exists; skipped when node_modules already exists.
//   - Rust:   `cargo fetch` (materializes the registry cache `cargo metadata`
//     needs; runs no build scripts).
//   - Go:     no-op — `go list`/the plugin resolve statically from go.mod/go.sum.
//   - Lockfile-static ecosystems (maven/nuget/php/ruby/elixir/dart/swift): no-op — resolved
//     statically from the lockfile; no install required.
//   - Python: no-op (DEFERRED). Installing PyPI sdists executes setup.py / build
//     backends, a code-execution risk a security scanner must not take by
//     default. Users install their venv themselves; the plugin reads it.
func installDependencies(ctx context.Context, eco ecosystems, moduleRoot string, offline bool) {
	if offline {
		// Offline mode never installs: there is no network to fetch from, and the
		// caller already guards on !offline. Defensive double-check.
		return
	}

	if eco.active("js") {
		runInstallPlan(ctx, "js", moduleRoot, selectJSInstall(moduleRoot))
	}
	if eco.active("rust") {
		runInstallPlan(ctx, "rust", moduleRoot, selectRustInstall())
	}
	// Go, the lockfile-static ecosystems, and Python are intentionally no-ops here (see doc comment).
}

// runInstallPlan executes one install plan, emitting an informational line before
// the run and a warning (never an error) on failure. A skip plan is silent.
func runInstallPlan(ctx context.Context, eco, dir string, plan installPlan) {
	if plan.skip {
		return
	}
	fmt.Fprintf(os.Stderr, "installing %s dependencies via %s (scripts disabled)...\n", eco, plan.pm)
	if err := runInstallCommand(ctx, dir, plan.pm, plan.args); err != nil {
		fmt.Fprintf(os.Stderr,
			"warning: %s dependency install via %s failed: %v; continuing with existing dependencies\n",
			eco, plan.pm, err)
	}
}

// selectJSInstall chooses the JS package-manager invocation for moduleRoot.
//
// Package-manager selection is driven by the lockfile present:
//   - pnpm-lock.yaml    → pnpm install --frozen-lockfile --ignore-scripts
//   - yarn.lock         → yarn install --ignore-scripts (classic flags)
//   - package-lock.json → npm ci --ignore-scripts
//   - (no lockfile)     → npm install --ignore-scripts
//
// --ignore-scripts is ALWAYS present (security invariant). --frozen-lockfile is
// added for pnpm only because a lockfile is required to select pnpm in the first
// place; npm uses `ci` (which itself requires a lockfile) when a lockfile exists
// and falls back to `install` otherwise.
//
// Yarn uses classic (v1) flags unconditionally. A Yarn-berry (v2+) project will
// reject --ignore-scripts and the command fails — which the caller turns into a
// warn-and-continue. That is safe: a failed install runs no scripts. Berry users
// can pre-install their deps or pass --skip-deps-install.
//
// When node_modules already exists the install is skipped entirely: re-installing
// risks clobbering a CI-preinstalled tree, and the existing tree is what the
// plugin will analyze.
func selectJSInstall(moduleRoot string) installPlan {
	if dirExists(filepath.Join(moduleRoot, nodeModulesDir)) {
		return installPlan{skip: true, skipReason: nodeModulesDir + " already present"}
	}
	switch {
	case fileExists(filepath.Join(moduleRoot, "pnpm-lock.yaml")):
		return installPlan{pm: "pnpm", args: []string{"install", "--frozen-lockfile", "--ignore-scripts"}}
	case fileExists(filepath.Join(moduleRoot, "yarn.lock")):
		return installPlan{pm: "yarn", args: []string{"install", "--ignore-scripts"}}
	case fileExists(filepath.Join(moduleRoot, "package-lock.json")):
		return installPlan{pm: "npm", args: []string{"ci", "--ignore-scripts"}}
	default:
		// No lockfile: `npm ci` would fail (it requires a lockfile), so use install.
		return installPlan{pm: "npm", args: []string{"install", "--ignore-scripts"}}
	}
}

// selectRustInstall returns the Rust dependency-materialization plan. `cargo
// fetch` downloads the registry index + crate sources cargo metadata needs
// without executing build scripts (build.rs) or proc-macros — safe on untrusted
// repos.
func selectRustInstall() installPlan {
	return installPlan{pm: "cargo", args: []string{"fetch"}}
}

// fileExists reports whether path exists and is a regular (non-directory) file.
func fileExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir()
}

// dirExists reports whether path exists and is a directory.
func dirExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}
