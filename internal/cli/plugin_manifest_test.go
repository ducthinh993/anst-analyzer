package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/commit0-dev/commit0-analyzer/internal/advisory"
	commit0v1 "github.com/commit0-dev/commit0-analyzer/pkg/contract/commit0v1"
)

// ── buildLockfilePluginManifest ───────────────────────────────────────────────

func TestBuildLockfilePluginManifest_OverrideBin(t *testing.T) {
	// The override path disables the build: any existing file is accepted, and
	// the manifest is derived from the adapter's plugin base name + language.
	bin := filepath.Join(t.TempDir(), "commit0-nuget-reachability")
	require.NoError(t, os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755))

	adapter := EcosystemAdapter{
		Ecosystem:     advisory.EcosystemMaven,
		Language:      "dotnet",
		MaxConfidence: ceilingPackage,
		ParseLockfile: func(_ string) ([]ResolvedDep, bool, error) { return nil, true, nil },
		HasPlugin:     true,
		PluginName:    "nuget",
	}

	m, ok := buildLockfilePluginManifest(context.Background(), adapter, bin)
	require.True(t, ok)
	require.NotNil(t, m)
	assert.Equal(t, "nuget-reachability", m.Name, "manifest name derives from PluginName, not Language")
	assert.Equal(t, []string{"dotnet"}, m.Languages, "manifest languages is the adapter Language")
	assert.Equal(t, "sca", m.Pillar)
	assert.NotEmpty(t, m.SHA256, "the override binary must be hash-pinned")
	absBin, _ := filepath.Abs(bin)
	assert.Equal(t, absBin, m.ExecPath)
}

func TestBuildLockfilePluginManifest_AbsentBinary(t *testing.T) {
	adapter := EcosystemAdapter{
		Language:      "dotnet",
		MaxConfidence: ceilingPackage,
		ParseLockfile: func(_ string) ([]ResolvedDep, bool, error) { return nil, true, nil },
		HasPlugin:     true,
		PluginName:    "nuget",
	}
	// A nonexistent override binary → (nil, false); the caller degrades to the
	// direct lockfile finding (fallback), never a silent skip.
	m, ok := buildLockfilePluginManifest(context.Background(), adapter, filepath.Join(t.TempDir(), "does-not-exist"))
	assert.False(t, ok)
	assert.Nil(t, m)
}

// ── suppressDirectLockfileFinding (both directions of the fallback) ────────────

func TestSuppressDirectLockfileFinding(t *testing.T) {
	graduated := EcosystemAdapter{Language: "dotnet", HasPlugin: true}
	plain := EcosystemAdapter{Language: "java", HasPlugin: false}

	assert.True(t, suppressDirectLockfileFinding(graduated, true),
		"graduated + plugin running → suppress the direct finding (plugin owns the verdict)")
	assert.False(t, suppressDirectLockfileFinding(graduated, false),
		"graduated but plugin absent → keep the direct finding (fallback, never a silent skip)")
	assert.False(t, suppressDirectLockfileFinding(plain, true),
		"non-graduated adapter always keeps its direct finding")
	assert.False(t, suppressDirectLockfileFinding(plain, false))
}

// ── newDirectLockfileFinding (the fallback finding is identical to pre-graduation) ──

func TestNewDirectLockfileFinding_PackageReachable(t *testing.T) {
	adapter := EcosystemAdapter{Language: "java", MaxConfidence: ceilingPackage}
	dep := advisoryDep{Module: "org.example:lib"}
	adv := &advisory.Advisory{ID: "CVE-9", Aliases: []string{"GHSA-x"}}

	f := newDirectLockfileFinding(adapter, dep, adv)
	assert.Equal(t, commit0v1.Confidence_CONFIDENCE_PACKAGE_REACHABLE, f.GetConfidence())
	assert.False(t, f.GetIncomplete())
	assert.Equal(t, "org.example:lib", f.GetModule())
	assert.Equal(t, "CVE-9", f.GetAdvisory().GetId())
	assert.Equal(t, []string{"GHSA-x"}, f.GetAdvisory().GetAliases())
	assert.Equal(t, "sca", f.GetPillar())
	assert.Equal(t, "java", f.GetLanguage())
}

func TestNewDirectLockfileFinding_IncompleteAdvisoryDegradesToUnknown(t *testing.T) {
	adapter := EcosystemAdapter{Language: "java", MaxConfidence: ceilingPackage}
	adv := &advisory.Advisory{ID: "CVE-9", Incomplete: true}
	f := newDirectLockfileFinding(adapter, advisoryDep{Module: "m"}, adv)
	assert.Equal(t, commit0v1.Confidence_CONFIDENCE_UNKNOWN, f.GetConfidence(),
		"an undecidable advisory match must degrade to UNKNOWN (never a false clean)")
	assert.True(t, f.GetIncomplete())
}

// ── resolvedDepsForAdapter / protoEcosystem ───────────────────────────────────

func TestResolvedDepsForAdapter(t *testing.T) {
	adapter := EcosystemAdapter{Ecosystem: advisory.EcosystemMaven, Language: "java"}
	deps := []ResolvedDep{
		{Name: "org.example:a", Version: "1.0", DepType: "runtime"},
		{Name: "org.example:b", Version: "2.0", DepType: "dev"},
	}
	out := resolvedDepsForAdapter(adapter, deps)
	require.Len(t, out, 2)
	assert.Equal(t, "org.example:a", out[0].GetName())
	assert.Equal(t, "1.0", out[0].GetVersion())
	assert.Equal(t, "runtime", out[0].GetDepType())
	assert.Equal(t, commit0v1.Ecosystem_ECOSYSTEM_MAVEN, out[0].GetEcosystem())
	assert.Equal(t, "dev", out[1].GetDepType())

	assert.Nil(t, resolvedDepsForAdapter(adapter, nil), "empty closure → nil resolved_deps")
}

func TestProtoEcosystem(t *testing.T) {
	assert.Equal(t, commit0v1.Ecosystem_ECOSYSTEM_MAVEN, protoEcosystem(advisory.EcosystemMaven))
	assert.Equal(t, commit0v1.Ecosystem_ECOSYSTEM_GO, protoEcosystem(advisory.EcosystemGo))
	assert.Equal(t, commit0v1.Ecosystem_ECOSYSTEM_UNKNOWN, protoEcosystem("Packagist"),
		"an ecosystem without a dedicated enum value maps to UNKNOWN until its phase adds one")
}
