package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeFile creates an empty file at path, creating parent dirs as needed.
func writeFile(t *testing.T, path string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte("{}"), 0o644))
}

// capturedInstall records one runInstallCommand invocation.
type capturedInstall struct {
	dir  string
	pm   string
	args []string
}

// stubRunner replaces runInstallCommand for the duration of a test, capturing
// every invocation and returning the supplied error. It restores the original on
// cleanup.
func stubRunner(t *testing.T, retErr error) *[]capturedInstall {
	t.Helper()
	var calls []capturedInstall
	orig := runInstallCommand
	runInstallCommand = func(_ context.Context, dir, pm string, args []string) error {
		calls = append(calls, capturedInstall{dir: dir, pm: pm, args: args})
		return retErr
	}
	t.Cleanup(func() { runInstallCommand = orig })
	return &calls
}

func TestSelectJSInstall_pnpmFrozenWithLockfile(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "pnpm-lock.yaml"))

	plan := selectJSInstall(root)

	assert.False(t, plan.skip)
	assert.Equal(t, "pnpm", plan.pm)
	assert.True(t, slices.Contains(plan.args, "--frozen-lockfile"), "pnpm with a lockfile must be frozen")
	assert.True(t, slices.Contains(plan.args, "--ignore-scripts"), "scripts must always be disabled")
}

func TestSelectJSInstall_yarnClassicFlags(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "yarn.lock"))

	plan := selectJSInstall(root)

	assert.Equal(t, "yarn", plan.pm)
	assert.True(t, slices.Contains(plan.args, "--ignore-scripts"), "scripts must always be disabled")
	assert.False(t, slices.Contains(plan.args, "--frozen-lockfile"), "yarn classic uses --ignore-scripts, not --frozen-lockfile")
}

func TestSelectJSInstall_npmCiWithLockfile(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package-lock.json"))

	plan := selectJSInstall(root)

	assert.Equal(t, "npm", plan.pm)
	assert.Equal(t, []string{"ci", "--ignore-scripts"}, plan.args)
}

func TestSelectJSInstall_npmInstallWithoutLockfile(t *testing.T) {
	root := t.TempDir()
	// Only package.json, no lockfile.
	writeFile(t, filepath.Join(root, "package.json"))

	plan := selectJSInstall(root)

	assert.Equal(t, "npm", plan.pm)
	assert.Equal(t, []string{"install", "--ignore-scripts"}, plan.args)
	assert.False(t, slices.Contains(plan.args, "--frozen-lockfile"), "no lockfile ⇒ no frozen install")
}

func TestSelectJSInstall_ignoreScriptsAlwaysPresent(t *testing.T) {
	// Every package-manager path must disable lifecycle scripts.
	for _, lock := range []string{"pnpm-lock.yaml", "yarn.lock", "package-lock.json", ""} {
		root := t.TempDir()
		if lock != "" {
			writeFile(t, filepath.Join(root, lock))
		}
		plan := selectJSInstall(root)
		assert.True(t, slices.Contains(plan.args, "--ignore-scripts"),
			"lockfile %q: --ignore-scripts must be present", lock)
	}
}

func TestSelectJSInstall_skipWhenNodeModulesPresent(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package-lock.json"))
	require.NoError(t, os.MkdirAll(filepath.Join(root, nodeModulesDir), 0o755))

	plan := selectJSInstall(root)

	assert.True(t, plan.skip, "an existing node_modules tree must not be clobbered")
	assert.NotEmpty(t, plan.skipReason)
}

func TestSelectRustInstall_cargoFetch(t *testing.T) {
	plan := selectRustInstall()
	assert.Equal(t, "cargo", plan.pm)
	assert.Equal(t, []string{"fetch"}, plan.args)
}

func TestInstallDependencies_offlineSkipsEverything(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package-lock.json"))
	calls := stubRunner(t, nil)

	installDependencies(context.Background(), ecosystems{"js": true, "rust": true}, root, true /* offline */)

	assert.Empty(t, *calls, "offline mode must never run an installer")
}

func TestInstallDependencies_jsInvokesChosenCommand(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "pnpm-lock.yaml"))
	calls := stubRunner(t, nil)

	installDependencies(context.Background(), ecosystems{"js": true}, root, false)

	require.Len(t, *calls, 1)
	got := (*calls)[0]
	assert.Equal(t, "pnpm", got.pm)
	assert.Equal(t, root, got.dir)
	assert.True(t, slices.Contains(got.args, "--ignore-scripts"))
	assert.True(t, slices.Contains(got.args, "--frozen-lockfile"))
}

func TestInstallDependencies_skipsWhenNodeModulesPresent(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package-lock.json"))
	require.NoError(t, os.MkdirAll(filepath.Join(root, nodeModulesDir), 0o755))
	calls := stubRunner(t, nil)

	installDependencies(context.Background(), ecosystems{"js": true}, root, false)

	assert.Empty(t, *calls, "node_modules present ⇒ no install")
}

func TestInstallDependencies_failureWarnsAndContinues(t *testing.T) {
	// A failing JS install (e.g. missing package-manager binary) must not abort the
	// scan; the Rust install must still run.
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package-lock.json"))
	writeFile(t, filepath.Join(root, "Cargo.toml"))
	calls := stubRunner(t, errors.New("npm not found on PATH"))

	installDependencies(context.Background(), ecosystems{"js": true, "rust": true}, root, false)

	// Both ecosystems were attempted despite the JS failure.
	require.Len(t, *calls, 2)
	assert.Equal(t, "npm", (*calls)[0].pm)
	assert.Equal(t, "cargo", (*calls)[1].pm)
}

func TestInstallDependencies_rustRunsCargoFetch(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "Cargo.toml"))
	calls := stubRunner(t, nil)

	installDependencies(context.Background(), ecosystems{"rust": true}, root, false)

	require.Len(t, *calls, 1)
	assert.Equal(t, "cargo", (*calls)[0].pm)
	assert.Equal(t, []string{"fetch"}, (*calls)[0].args)
	assert.Equal(t, root, (*calls)[0].dir)
}

func TestInstallDependencies_goAndPythonAreNoOps(t *testing.T) {
	root := t.TempDir()
	calls := stubRunner(t, nil)

	installDependencies(context.Background(), ecosystems{"go": true, "python": true, "java": true}, root, false)

	assert.Empty(t, *calls, "Go/Python/Lane-A must not trigger an install")
}
