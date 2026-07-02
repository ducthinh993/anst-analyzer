package contract_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/commit0-dev/commit0-analyzer/pkg/contract"
)

func TestProtocolVersion_Present(t *testing.T) {
	// ProtocolVersion must be a non-empty string constant.
	require.NotEmpty(t, contract.ProtocolVersion, "ProtocolVersion must be set")
}

func TestProtocolVersion_MajorAndMinor(t *testing.T) {
	// Major and Minor must be separately accessible.
	assert.GreaterOrEqual(t, contract.ProtocolMajor, 0, "ProtocolMajor must be >= 0")
	assert.GreaterOrEqual(t, contract.ProtocolMinor, 0, "ProtocolMinor must be >= 0")
}

func TestCompatible_SameVersion(t *testing.T) {
	// Equal major and minor must be compatible.
	assert.True(t, contract.Compatible(contract.ProtocolMajor, contract.ProtocolMinor),
		"plugin with same major.minor must be compatible")
}

func TestCompatible_RejectsMajorMismatch(t *testing.T) {
	// A different major version is always incompatible, regardless of minor.
	wrongMajor := contract.ProtocolMajor + 1
	assert.False(t, contract.Compatible(wrongMajor, contract.ProtocolMinor),
		"plugin with higher major must be rejected")

	if contract.ProtocolMajor > 0 {
		assert.False(t, contract.Compatible(contract.ProtocolMajor-1, contract.ProtocolMinor),
			"plugin with lower major must be rejected")
	}
}

func TestCompatible_AcceptsLowerOrEqualMinor(t *testing.T) {
	// Host minor >= plugin minor: plugin asks for at most what the host supports.
	// Plugin minor == host minor: compatible.
	assert.True(t, contract.Compatible(contract.ProtocolMajor, contract.ProtocolMinor),
		"equal minor must be compatible")

	// Plugin minor < host minor: plugin needs fewer features, host can serve it.
	if contract.ProtocolMinor > 0 {
		assert.True(t, contract.Compatible(contract.ProtocolMajor, contract.ProtocolMinor-1),
			"plugin with lower minor must be compatible")
	}
}

func TestCompatible_RejectsHigherMinor(t *testing.T) {
	// Plugin minor > host minor: plugin requires features the host doesn't have.
	higherMinor := contract.ProtocolMinor + 1
	assert.False(t, contract.Compatible(contract.ProtocolMajor, higherMinor),
		"plugin with higher minor than host must be rejected")
}

// TestCompatible_Minor2Contract pins the resolved_deps minor bump (1→2). The
// host is now at minor 2; it must accept a plugin advertising minor 2 (a
// lockfile-backed plugin that consumes resolved_deps) and reject minor 3.
func TestCompatible_Minor2Contract(t *testing.T) {
	assert.Equal(t, 2, contract.ProtocolMinor,
		"resolved_deps is an additive minor bump; ProtocolMinor must be 2")
	assert.Equal(t, "0.2", contract.ProtocolVersion,
		"ProtocolVersion must track the minor bump")

	assert.True(t, contract.Compatible(0, 2),
		"a plugin at minor 2 (advertises resolved_deps support) must be accepted by host 2")
	assert.False(t, contract.Compatible(0, 3),
		"a plugin at minor 3 requires fields host 2 does not send; must be rejected")
}

// TestCompatible_OlderMinorStillLoads is the backward-compatibility guarantee:
// existing plugins that predate the resolved_deps field advertise minor 1 (or
// 0) and must continue to load against host 2. The bump is purely additive.
func TestCompatible_OlderMinorStillLoads(t *testing.T) {
	assert.True(t, contract.Compatible(0, 1),
		"a pre-resolved_deps plugin at minor 1 must still load (additive bump)")
	assert.True(t, contract.Compatible(0, 0),
		"a plugin at minor 0 must still load against host 2")
}
