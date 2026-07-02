package contract

import "fmt"

// ProtocolMajor and ProtocolMinor define the current host protocol version.
//
// This contract is v0-PROVISIONAL: the schema is not frozen until Phase 2
// confirms that the chosen transport (subprocess/gRPC over stdio) can carry
// the streaming Analyze RPC without breaking changes. Only after Phase 2
// validation is ProtocolMajor bumped from 0 to a frozen 0.
//
// Compatibility rule (host perspective):
//   - A plugin is accepted when plugin.Major == host.Major AND
//     plugin.Minor <= host.Minor.
//   - Same major, lower-or-equal plugin minor: host supports everything
//     the plugin needs (additive minor bumps only).
//   - Same major, higher plugin minor: plugin requires fields the host does
//     not know — reject.
//   - Different major: breaking change — always reject.
const (
	ProtocolMajor = 0
	ProtocolMinor = 2

	// ProtocolVersion is the canonical "major.minor" string, e.g. "0.2".
	ProtocolVersion = "0.2"
)

// Compatible reports whether a plugin at (remoteMajor, remoteMinor) is
// compatible with this host.
//
// The host accepts the plugin when:
//   - remoteMajor == ProtocolMajor  (same major series)
//   - remoteMinor <= ProtocolMinor  (host minor >= plugin minor)
//
// A plugin that advertises a higher minor than the host is rejected: it may
// depend on fields the host does not send. A different major is always
// incompatible (breaking wire changes).
func Compatible(remoteMajor, remoteMinor int) bool {
	return remoteMajor == ProtocolMajor && remoteMinor <= ProtocolMinor
}

// VersionString returns the canonical "major.minor" representation of an
// arbitrary version pair, useful for logging and error messages.
func VersionString(major, minor int) string {
	return fmt.Sprintf("%d.%d", major, minor)
}
