package analyzer

import (
	commit0v1 "github.com/commit0-dev/commit0-analyzer/pkg/contract/commit0v1"
)

// Owned returns the advisories from byEco (keyed by OSV ecosystem name) that
// belong to any ecosystem in ecosystems. Order follows the ecosystems slice, then
// the per-ecosystem accumulation order, so routing is deterministic.
//
// It is the per-analyzer routing primitive: an analyzer only ever sees advisories
// for the ecosystems it owns, so a polyglot scan cannot leak (for example) an npm
// advisory into the Dart analyzer or a subprocess plugin. This is the
// by-construction fix for the cross-ecosystem advisory broadcast — it applies
// equally to in-process analyzers and to subprocess plugins, because the host
// filters each transport's request through this helper.
func Owned(byEco map[string][]*commit0v1.Advisory, ecosystems []string) []*commit0v1.Advisory {
	var out []*commit0v1.Advisory
	for _, e := range ecosystems {
		out = append(out, byEco[e]...)
	}
	return out
}

// Partition splits byEco into the advisories owned by ownedEcosystems and the
// rest (unowned). It exists to make the no-orphan invariant checkable:
//
//	len(routed) + len(unowned) == total advisories across byEco
//
// An unowned advisory (no analyzer or plugin claims its ecosystem) keeps its
// existing host-side handling — it is degraded, never dropped.
func Partition(byEco map[string][]*commit0v1.Advisory, ownedEcosystems map[string]bool) (routed, unowned []*commit0v1.Advisory) {
	for eco, advs := range byEco {
		if ownedEcosystems[eco] {
			routed = append(routed, advs...)
		} else {
			unowned = append(unowned, advs...)
		}
	}
	return routed, unowned
}
