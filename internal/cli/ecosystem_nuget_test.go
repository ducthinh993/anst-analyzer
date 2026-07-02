package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/commit0-dev/commit0-analyzer/internal/advisory"
)

// ── adapter registration ──────────────────────────────────────────────────────

// TestNugetAdapterRegistered verifies that the NuGet lockfile-static adapter is
// registered in the global registry with the expected metadata.
func TestNugetAdapterRegistered(t *testing.T) {
	var found *EcosystemAdapter
	for _, a := range EcosystemAdapters() {
		if a.Language == "dotnet" {
			a := a
			found = &a
			break
		}
	}
	require.NotNil(t, found, "NuGet adapter with Language=dotnet must be registered")
	assert.Equal(t, advisory.EcosystemNuGet, found.Ecosystem, "Ecosystem must be 'NuGet'")
	assert.Nil(t, found.NormalizeName, "NormalizeName must be nil (NuGet uses canonical casing)")
	assert.Contains(t, found.DetectFiles, "packages.lock.json")
	assert.Contains(t, found.DetectFiles, "packages.config")
	assert.Contains(t, found.DetectFiles, "*.csproj")
}

// ── detectEcosystems integration ─────────────────────────────────────────────

// TestDetectEcosystems_PackagesLockJSON verifies that packages.lock.json triggers
// NuGet ecosystem detection.
func TestDetectEcosystems_PackagesLockJSON(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "packages.lock.json"),
		[]byte(packagesLockJSONSingleDep), 0o644))

	eco := detectEcosystems(dir)
	assert.True(t, eco.active("dotnet"), "packages.lock.json present → .NET ecosystem detected")
	assert.False(t, eco.active("go"), "no go.mod → Go not detected")
}

// TestDetectEcosystems_PackagesConfig verifies that packages.config triggers
// NuGet ecosystem detection.
func TestDetectEcosystems_PackagesConfig(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "packages.config"),
		[]byte(packagesConfigSingle), 0o644))

	eco := detectEcosystems(dir)
	assert.True(t, eco.active("dotnet"), "packages.config present → .NET ecosystem detected")
}

// TestDetectEcosystems_Csproj verifies that a *.csproj file triggers NuGet
// ecosystem detection via the glob pattern "*.csproj".
func TestDetectEcosystems_Csproj(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "MyApp.csproj"),
		[]byte(csprojSingleDep), 0o644))

	eco := detectEcosystems(dir)
	assert.True(t, eco.active("dotnet"), "*.csproj present → .NET ecosystem detected via glob")
}

// ── packages.lock.json parsing ───────────────────────────────────────────────

// TestParsePackagesLockJSON_SingleDep verifies a single runtime dep is parsed correctly.
func TestParsePackagesLockJSON_SingleDep(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "packages.lock.json"),
		[]byte(packagesLockJSONSingleDep), 0o644))

	deps, complete, err := parsePackagesLockJSON(filepath.Join(dir, "packages.lock.json"))
	require.NoError(t, err)
	assert.True(t, complete, "packages.lock.json present → complete=true")
	require.Len(t, deps, 1)
	assert.Equal(t, "Newtonsoft.Json", deps[0].Name)
	assert.Equal(t, "13.0.3", deps[0].Version)
	assert.Equal(t, "runtime", deps[0].DepType)
}

// TestParsePackagesLockJSON_TestSDK documents the conservative behaviour: packages.lock.json
// carries no PrivateAssets metadata, so every package — including well-known test SDKs —
// defaults to DepType="runtime". This is intentional: unknown ≠ safe; we must not suppress
// a real runtime advisory because a name happened to match a test-SDK prefix.
// Authoritative dev/test segmentation requires the .csproj (see TestParseCsprojDir_PrivateAssetsAll).
func TestParsePackagesLockJSON_TestSDK(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "packages.lock.json"),
		[]byte(packagesLockJSONWithTestSDK), 0o644))

	deps, complete, err := parsePackagesLockJSON(filepath.Join(dir, "packages.lock.json"))
	require.NoError(t, err)
	assert.True(t, complete)

	byName := make(map[string]ResolvedDep)
	for _, d := range deps {
		byName[d.Name] = d
	}

	xunit, ok := byName["xunit"]
	require.True(t, ok, "xunit must be present")
	assert.Equal(t, "runtime", xunit.DepType,
		"xunit in packages.lock.json → DepType=runtime (no PrivateAssets metadata; conservative default)")

	nj, ok := byName["Newtonsoft.Json"]
	require.True(t, ok, "Newtonsoft.Json must be present")
	assert.Equal(t, "runtime", nj.DepType, "Newtonsoft.Json → DepType=runtime")
}

// TestParsePackagesLockJSON_MultipleTFMs verifies that packages are deduplicated
// when they appear under multiple target framework monikers.
func TestParsePackagesLockJSON_MultipleTFMs(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "packages.lock.json"),
		[]byte(packagesLockJSONMultiTFM), 0o644))

	deps, complete, err := parsePackagesLockJSON(filepath.Join(dir, "packages.lock.json"))
	require.NoError(t, err)
	assert.True(t, complete)
	// "Newtonsoft.Json" appears under two TFMs but must be deduplicated to one entry.
	count := 0
	for _, d := range deps {
		if d.Name == "Newtonsoft.Json" {
			count++
		}
	}
	assert.Equal(t, 1, count, "same package under multiple TFMs must be deduplicated")
}

// TestParsePackagesLockJSON_ProjectRefSkipped verifies that project references
// (type="Project") are not included in the dep list.
func TestParsePackagesLockJSON_ProjectRefSkipped(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "packages.lock.json"),
		[]byte(packagesLockJSONWithProjectRef), 0o644))

	deps, complete, err := parsePackagesLockJSON(filepath.Join(dir, "packages.lock.json"))
	require.NoError(t, err)
	assert.True(t, complete)
	for _, d := range deps {
		assert.NotEqual(t, "MyOtherProject", d.Name, "project references must be skipped")
	}
}

// TestParsePackagesLockJSON_Absent verifies that a missing packages.lock.json
// returns complete=false without error (caller tries next source).
func TestParsePackagesLockJSON_Absent(t *testing.T) {
	deps, complete, err := parsePackagesLockJSON(filepath.Join(t.TempDir(), "packages.lock.json"))
	require.NoError(t, err)
	assert.False(t, complete)
	assert.Nil(t, deps)
}

// TestParsePackagesLockJSON_Malformed verifies that a malformed JSON returns an error.
func TestParsePackagesLockJSON_Malformed(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "packages.lock.json"),
		[]byte("not valid json {"), 0o644))

	_, complete, err := parsePackagesLockJSON(filepath.Join(dir, "packages.lock.json"))
	assert.Error(t, err, "malformed JSON must return an error")
	assert.False(t, complete)
}

// TestParsePackagesLockJSON_Empty verifies that a lockfile with no packages
// returns complete=true with an empty dep list (project has no deps — valid).
func TestParsePackagesLockJSON_Empty(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "packages.lock.json"),
		[]byte(packagesLockJSONEmpty), 0o644))

	deps, complete, err := parsePackagesLockJSON(filepath.Join(dir, "packages.lock.json"))
	require.NoError(t, err)
	assert.True(t, complete, "empty lockfile → complete=true (project has no deps)")
	assert.Empty(t, deps)
}

// ── project.assets.json parsing ──────────────────────────────────────────────

// TestParseProjectAssetsJSON_SingleDep verifies parsing of a minimal project.assets.json.
func TestParseProjectAssetsJSON_SingleDep(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "obj"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "obj", "project.assets.json"),
		[]byte(projectAssetsJSONSingleDep), 0o644))

	deps, complete, err := parseProjectAssetsJSON(filepath.Join(dir, "obj", "project.assets.json"))
	require.NoError(t, err)
	assert.True(t, complete)
	require.Len(t, deps, 1)
	assert.Equal(t, "Newtonsoft.Json", deps[0].Name)
	assert.Equal(t, "13.0.3", deps[0].Version)
	assert.Equal(t, "runtime", deps[0].DepType)
}

// TestParseProjectAssetsJSON_ProjectRefSkipped verifies that project references
// (type="project") in project.assets.json are not included.
func TestParseProjectAssetsJSON_ProjectRefSkipped(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "obj"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "obj", "project.assets.json"),
		[]byte(projectAssetsJSONWithProjectRef), 0o644))

	deps, complete, err := parseProjectAssetsJSON(filepath.Join(dir, "obj", "project.assets.json"))
	require.NoError(t, err)
	assert.True(t, complete)
	for _, d := range deps {
		assert.NotEqual(t, "SomeLibrary", d.Name, "project references must be skipped")
	}
}

// TestParseProjectAssetsJSON_MultipleRIDsDeduplicated verifies that the same
// package under multiple RIDs (runtime identifiers) is deduplicated.
func TestParseProjectAssetsJSON_MultipleRIDsDeduplicated(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "obj"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "obj", "project.assets.json"),
		[]byte(projectAssetsJSONMultiRID), 0o644))

	deps, complete, err := parseProjectAssetsJSON(filepath.Join(dir, "obj", "project.assets.json"))
	require.NoError(t, err)
	assert.True(t, complete)

	count := 0
	for _, d := range deps {
		if d.Name == "Newtonsoft.Json" {
			count++
		}
	}
	assert.Equal(t, 1, count, "same package under multiple RIDs must be deduplicated")
}

// TestParseProjectAssetsJSON_Absent verifies that missing project.assets.json
// returns complete=false without error.
func TestParseProjectAssetsJSON_Absent(t *testing.T) {
	deps, complete, err := parseProjectAssetsJSON(filepath.Join(t.TempDir(), "obj", "project.assets.json"))
	require.NoError(t, err)
	assert.False(t, complete)
	assert.Nil(t, deps)
}

// ── packages.config parsing ──────────────────────────────────────────────────

// TestParsePackagesConfig_Runtime verifies a single runtime dep.
func TestParsePackagesConfig_Runtime(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "packages.config"),
		[]byte(packagesConfigSingle), 0o644))

	deps, complete, err := parsePackagesConfig(filepath.Join(dir, "packages.config"))
	require.NoError(t, err)
	assert.True(t, complete)
	require.Len(t, deps, 1)
	assert.Equal(t, "Newtonsoft.Json", deps[0].Name)
	assert.Equal(t, "13.0.3", deps[0].Version)
	assert.Equal(t, "runtime", deps[0].DepType)
}

// TestParsePackagesConfig_DevDependency verifies that developmentDependency="true"
// is mapped to DepType="dev".
func TestParsePackagesConfig_DevDependency(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "packages.config"),
		[]byte(packagesConfigWithDev), 0o644))

	deps, complete, err := parsePackagesConfig(filepath.Join(dir, "packages.config"))
	require.NoError(t, err)
	assert.True(t, complete)

	byName := make(map[string]ResolvedDep)
	for _, d := range deps {
		byName[d.Name] = d
	}

	require.Contains(t, byName, "Newtonsoft.Json")
	assert.Equal(t, "runtime", byName["Newtonsoft.Json"].DepType)

	require.Contains(t, byName, "StyleCop.Analyzers")
	assert.Equal(t, "dev", byName["StyleCop.Analyzers"].DepType,
		"developmentDependency=true → DepType=dev")
}

// TestParsePackagesConfig_Absent verifies missing packages.config returns complete=false.
func TestParsePackagesConfig_Absent(t *testing.T) {
	deps, complete, err := parsePackagesConfig(filepath.Join(t.TempDir(), "packages.config"))
	require.NoError(t, err)
	assert.False(t, complete)
	assert.Nil(t, deps)
}

// TestParsePackagesConfig_Malformed verifies that malformed XML returns an error.
func TestParsePackagesConfig_Malformed(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "packages.config"),
		[]byte("<packages><package id="), 0o644))

	_, complete, err := parsePackagesConfig(filepath.Join(dir, "packages.config"))
	assert.Error(t, err, "malformed XML must return an error")
	assert.False(t, complete)
}

// ── .csproj fallback ─────────────────────────────────────────────────────────

// TestParseCsprojDir_SingleDep verifies that a .csproj with one PackageReference
// is parsed and returns complete=false (transitives unknown).
func TestParseCsprojDir_SingleDep(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "MyApp.csproj"),
		[]byte(csprojSingleDep), 0o644))

	deps, complete, err := parseCsprojDir(dir)
	require.NoError(t, err)
	assert.False(t, complete, "csproj-only → complete=false (transitives unknown without dotnet restore)")
	require.Len(t, deps, 1)
	assert.Equal(t, "Newtonsoft.Json", deps[0].Name)
	assert.Equal(t, "13.0.3", deps[0].Version)
	assert.Equal(t, "runtime", deps[0].DepType)
}

// TestParseCsprojDir_PrivateAssetsAll verifies that PrivateAssets="All" sets DepType=dev.
func TestParseCsprojDir_PrivateAssetsAll(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "MyApp.csproj"),
		[]byte(csprojWithPrivateAssets), 0o644))

	deps, complete, err := parseCsprojDir(dir)
	require.NoError(t, err)
	assert.False(t, complete)

	byName := make(map[string]ResolvedDep)
	for _, d := range deps {
		byName[d.Name] = d
	}

	require.Contains(t, byName, "Newtonsoft.Json")
	assert.Equal(t, "runtime", byName["Newtonsoft.Json"].DepType)

	require.Contains(t, byName, "Microsoft.CodeAnalysis.NetAnalyzers")
	assert.Equal(t, "dev", byName["Microsoft.CodeAnalysis.NetAnalyzers"].DepType,
		"PrivateAssets=All → DepType=dev")
}

// TestParseCsprojDir_NoPrivateAssetsDefaultsRuntime documents that a .csproj PackageReference
// without <PrivateAssets>All</PrivateAssets> defaults to DepType="runtime", even when the
// package name looks like a test SDK. The only authoritative dev/test marker is PrivateAssets=All
// (see TestParseCsprojDir_PrivateAssetsAll). Name-prefix heuristics are intentionally absent:
// a runtime package whose name resembles a test SDK must not be incorrectly suppressed.
func TestParseCsprojDir_NoPrivateAssetsDefaultsRuntime(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "MyTests.csproj"),
		[]byte(csprojWithTestSDK), 0o644))

	deps, complete, err := parseCsprojDir(dir)
	require.NoError(t, err)
	assert.False(t, complete)

	byName := make(map[string]ResolvedDep)
	for _, d := range deps {
		byName[d.Name] = d
	}

	require.Contains(t, byName, "xunit")
	assert.Equal(t, "runtime", byName["xunit"].DepType,
		"xunit without PrivateAssets=All → DepType=runtime (conservative; no name-prefix heuristic)")

	require.Contains(t, byName, "Microsoft.NET.Test.Sdk")
	assert.Equal(t, "runtime", byName["Microsoft.NET.Test.Sdk"].DepType,
		"Microsoft.NET.Test.Sdk without PrivateAssets=All → DepType=runtime")
}

// TestParseCsprojDir_NoCsproj verifies that a directory with no *.csproj files
// returns (nil, false, nil) without error.
func TestParseCsprojDir_NoCsproj(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "README.md"), []byte("readme"), 0o644))

	deps, complete, err := parseCsprojDir(dir)
	require.NoError(t, err)
	assert.False(t, complete)
	assert.Nil(t, deps)
}

// TestParseCsprojDir_MissingVersion verifies that a PackageReference without a
// Version attribute is skipped (cannot query OSV without a pinned version).
func TestParseCsprojDir_MissingVersion(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "MyApp.csproj"),
		[]byte(csprojMissingVersion), 0o644))

	deps, complete, err := parseCsprojDir(dir)
	require.NoError(t, err)
	assert.False(t, complete)
	// The entry without a version must be skipped; the one with a version must remain.
	for _, d := range deps {
		assert.NotEmpty(t, d.Version, "deps without a version must be skipped")
	}
}

// ── parseNugetLockfile resolution priority ────────────────────────────────────

// TestParseNugetLockfile_PrefersPackagesLockJSON verifies that packages.lock.json
// is preferred over other sources when present.
func TestParseNugetLockfile_PrefersPackagesLockJSON(t *testing.T) {
	dir := t.TempDir()
	// Write packages.lock.json with one dep.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "packages.lock.json"),
		[]byte(packagesLockJSONSingleDep), 0o644))
	// Also write a .csproj with a different dep — should NOT be used.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "MyApp.csproj"),
		[]byte(csprojSingleDep), 0o644))

	deps, complete, err := parseNugetLockfile(dir)
	require.NoError(t, err)
	assert.True(t, complete, "packages.lock.json present → complete=true")
	// Result must come from packages.lock.json (Newtonsoft.Json 13.0.3).
	require.Len(t, deps, 1)
	assert.Equal(t, "Newtonsoft.Json", deps[0].Name)
}

// TestParseNugetLockfile_FallsBackToProjectAssets verifies that project.assets.json
// is used when packages.lock.json is absent.
func TestParseNugetLockfile_FallsBackToProjectAssets(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "obj"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "obj", "project.assets.json"),
		[]byte(projectAssetsJSONSingleDep), 0o644))

	deps, complete, err := parseNugetLockfile(dir)
	require.NoError(t, err)
	assert.True(t, complete)
	require.Len(t, deps, 1)
	assert.Equal(t, "Newtonsoft.Json", deps[0].Name)
}

// TestParseNugetLockfile_FallsBackToPackagesConfig verifies packages.config is
// used when neither lockfile is present.
func TestParseNugetLockfile_FallsBackToPackagesConfig(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "packages.config"),
		[]byte(packagesConfigSingle), 0o644))

	deps, complete, err := parseNugetLockfile(dir)
	require.NoError(t, err)
	assert.True(t, complete)
	require.Len(t, deps, 1)
	assert.Equal(t, "Newtonsoft.Json", deps[0].Name)
}

// TestParseNugetLockfile_CsprojOnly verifies that a .csproj-only project returns
// complete=false (transitives cannot be resolved without running dotnet restore).
func TestParseNugetLockfile_CsprojOnly(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "MyApp.csproj"),
		[]byte(csprojSingleDep), 0o644))

	deps, complete, err := parseNugetLockfile(dir)
	require.NoError(t, err)
	// complete=false: only direct deps; transitives unknown without dotnet restore.
	assert.False(t, complete, "csproj-only → complete=false (ACE-safe: dotnet restore not run)")
	assert.NotEmpty(t, deps, "declared deps from .csproj must be present")
}

// TestParseNugetLockfile_NoFiles verifies that a directory with no NuGet artifacts
// returns (nil, false, nil) — the ecosystem was not actually resolvable.
func TestParseNugetLockfile_NoFiles(t *testing.T) {
	dir := t.TempDir()
	deps, complete, err := parseNugetLockfile(dir)
	require.NoError(t, err)
	assert.False(t, complete)
	assert.Nil(t, deps)
}

// ── fixtures ──────────────────────────────────────────────────────────────────

const packagesLockJSONSingleDep = `{
  "version": 1,
  "dependencies": {
    ".NETCoreApp,Version=v6.0": {
      "Newtonsoft.Json": {
        "type": "Direct",
        "requested": "[13.0.3, )",
        "resolved": "13.0.3",
        "contentHash": "abc123"
      }
    }
  }
}`

const packagesLockJSONWithTestSDK = `{
  "version": 1,
  "dependencies": {
    ".NETCoreApp,Version=v6.0": {
      "Newtonsoft.Json": {
        "type": "Direct",
        "requested": "[13.0.3, )",
        "resolved": "13.0.3",
        "contentHash": "abc123"
      },
      "xunit": {
        "type": "Direct",
        "requested": "[2.4.2, )",
        "resolved": "2.4.2",
        "contentHash": "def456"
      }
    }
  }
}`

const packagesLockJSONMultiTFM = `{
  "version": 1,
  "dependencies": {
    ".NETCoreApp,Version=v6.0": {
      "Newtonsoft.Json": {
        "type": "Direct",
        "resolved": "13.0.3",
        "contentHash": "abc"
      }
    },
    ".NETCoreApp,Version=v8.0": {
      "Newtonsoft.Json": {
        "type": "Direct",
        "resolved": "13.0.3",
        "contentHash": "abc"
      }
    }
  }
}`

const packagesLockJSONWithProjectRef = `{
  "version": 1,
  "dependencies": {
    ".NETCoreApp,Version=v6.0": {
      "Newtonsoft.Json": {
        "type": "Direct",
        "resolved": "13.0.3",
        "contentHash": "abc"
      },
      "MyOtherProject": {
        "type": "Project",
        "resolved": "1.0.0",
        "contentHash": ""
      }
    }
  }
}`

const packagesLockJSONEmpty = `{
  "version": 1,
  "dependencies": {}
}`

const projectAssetsJSONSingleDep = `{
  "version": 3,
  "targets": {
    ".NETCoreApp,Version=v6.0": {
      "Newtonsoft.Json/13.0.3": {
        "type": "package",
        "compile": {"lib/net6.0/Newtonsoft.Json.dll": {}},
        "runtime": {"lib/net6.0/Newtonsoft.Json.dll": {}}
      }
    }
  }
}`

const projectAssetsJSONWithProjectRef = `{
  "version": 3,
  "targets": {
    ".NETCoreApp,Version=v6.0": {
      "Newtonsoft.Json/13.0.3": {
        "type": "package"
      },
      "SomeLibrary/1.0.0": {
        "type": "project"
      }
    }
  }
}`

const projectAssetsJSONMultiRID = `{
  "version": 3,
  "targets": {
    ".NETCoreApp,Version=v6.0/linux-x64": {
      "Newtonsoft.Json/13.0.3": {
        "type": "package"
      }
    },
    ".NETCoreApp,Version=v6.0/win-x64": {
      "Newtonsoft.Json/13.0.3": {
        "type": "package"
      }
    }
  }
}`

const packagesConfigSingle = `<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Newtonsoft.Json" version="13.0.3" targetFramework="net472" />
</packages>`

const packagesConfigWithDev = `<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Newtonsoft.Json" version="13.0.3" targetFramework="net472" />
  <package id="StyleCop.Analyzers" version="1.2.0" targetFramework="net472"
           developmentDependency="true" />
</packages>`

const csprojSingleDep = `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net6.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
  </ItemGroup>
</Project>`

const csprojWithPrivateAssets = `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net6.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
    <PackageReference Include="Microsoft.CodeAnalysis.NetAnalyzers" Version="7.0.0"
                      PrivateAssets="All" />
  </ItemGroup>
</Project>`

const csprojWithTestSDK = `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net6.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="xunit" Version="2.4.2" />
    <PackageReference Include="Microsoft.NET.Test.Sdk" Version="17.6.0" />
  </ItemGroup>
</Project>`

const csprojMissingVersion = `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="NoVersionPackage" />
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
  </ItemGroup>
</Project>`
