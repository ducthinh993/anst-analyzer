package lockfilekit

import "strings"

// Frontier describes a project's dynamism frontier: the set of constructs that
// could reference a package by name without a resolvable static import
// (reflection, eval, dynamic require/import, DI-by-name scanning, macros, method
// _missing, etc.). When a frontier is present, NO package can be proven
// unreachable — the decision procedure degrades every advisory to UNKNOWN.
//
// The zero value is an empty (absent) frontier. Each ecosystem plugin builds a
// Frontier by scanning source for its own language's dynamism markers and calls
// Add for every one it finds; the reasons are surfaced in the UNKNOWN finding so
// the user can see WHY the project could not be proven clean.
type Frontier struct {
	// Reasons is the ordered, de-duplicated list of dynamism markers found.
	Reasons []string
}

// Add records a dynamism marker. Duplicate reasons are ignored so the summary
// stays stable regardless of how many times a marker appears in source.
func (f *Frontier) Add(reason string) {
	if reason == "" {
		return
	}
	for _, r := range f.Reasons {
		if r == reason {
			return
		}
	}
	f.Reasons = append(f.Reasons, reason)
}

// Present reports whether the project has any dynamism frontier.
func (f Frontier) Present() bool { return len(f.Reasons) > 0 }

// Summary renders the reasons as a comma-separated string for a finding's reason
// property. Returns "none" when the frontier is empty.
func (f Frontier) Summary() string {
	if len(f.Reasons) == 0 {
		return "none"
	}
	return strings.Join(f.Reasons, ", ")
}
