package cli

// ecosystem_maven.go — lockfile-static adapter for Maven (Java/Kotlin/Scala).
//
// OSV ecosystem: "Maven" (covers all JVM languages that publish to Maven Central).
// Maximum confidence: PACKAGE_REACHABLE (OSV Maven advisories carry no method-level data).
//
// Security invariants (ACE-safety):
//   - NEVER evaluate build.gradle[.kts] — Groovy/Kotlin code = arbitrary code execution.
//   - NEVER run mvn, gradle, ./mvnw, ./gradlew, or any build tool wrapper.
//   - ONLY parse static files (gradle.lockfile, pom.xml).
//
// Lockfile / manifest strategy:
//   - gradle.lockfile present → parse full transitive closure → complete=true.
//   - pom.xml only (no gradle.lockfile) → parse declared direct deps statically
//     (encoding/xml; no mvn run) → complete=ALWAYS false.
//     Rationale: pom.xml lists only direct declared dependencies. The full transitive
//     closure requires `mvn help:effective-pom` (ACE risk). A project vulnerable only
//     through a TRANSITIVE dep would produce zero findings and exit 0 — a false-clean.
//     Returning complete=false ensures the caller marks the scan incomplete (exit 3),
//     never silently passing a pom.xml-only project as clean. "unknown ≠ safe".
//   - build.gradle only (no lockfile) → (nil, false, nil) → incomplete (ACE risk).

import (
	"bufio"
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"

	"github.com/commit0-dev/commit0-analyzer/internal/advisory"
)

func init() {
	// Register the real Maven (JVM) lockfile-static adapter.
	//
	// DetectFiles includes gradle.lockfile so that a project root containing only
	// gradle.lockfile (no build.gradle co-located) is still detected as a Java
	// project. Without it, detectEcosystems leaves java out of scope → the lockfile-static
	// loop is skipped → false-clean exit 0 (advisories never queried).
	RegisterEcosystemAdapter(EcosystemAdapter{
		Ecosystem:     advisory.EcosystemMaven,
		Language:      "java",
		DetectFiles:   []string{"pom.xml", "gradle.lockfile", "build.gradle", "build.gradle.kts"},
		MaxConfidence: ceilingPackage,
		ParseLockfile: parseMavenLockfile,
		// NormalizeName is nil: Maven coordinates (groupId:artifactId) are
		// case-sensitive and OSV records preserve their original casing.
		// Do NOT lowercase Maven names.
		NormalizeName: nil,
	})
}

// parseMavenLockfile is the EcosystemAdapter.ParseLockfile implementation for the
// Maven (JVM) ecosystem.
//
// Resolution priority:
//  1. gradle.lockfile — if present, parse it as the full transitive dep closure.
//     Returns (deps, true, nil). This is the only path that returns complete=true.
//  2. pom.xml — if present (and no gradle.lockfile), parse declared direct deps
//     statically (encoding/xml; NO mvn or any build tool). ALWAYS returns
//     complete=false: pom.xml covers only direct declared deps; the transitive
//     closure requires `mvn` (ACE risk). A project vulnerable only through a
//     transitive dep must NOT silently exit 0. complete=false ensures the scan
//     is marked incomplete (exit 3) so a clean pom.xml scan never exits 0.
//     Returns (deps, false, nil) when 1+ deps with concrete literal versions exist.
//     Returns (nil, false, nil) when pom.xml has no <dependencies> section, all
//     versions are undecidable (${...}/absent), or XML parse fails.
//  3. Nothing present — return (nil, false, nil).
func parseMavenLockfile(root string) ([]ResolvedDep, bool, error) {
	// Priority 1: gradle.lockfile — full transitive closure, machine-generated.
	// parseGradleLockfile returns (nil, false, nil) when the file is absent.
	if deps, complete, err := parseGradleLockfile(root); err != nil || complete {
		return deps, complete, err
	}
	// Priority 2: pom.xml — declared direct deps, static XML parse.
	return parsePomXML(root)
}

// parseGradleLockfile reads and parses a gradle.lockfile at root/gradle.lockfile.
//
// Gradle dependency locking (Gradle 4.8+) produces gradle.lockfile when a project
// enables `dependencyLocking {}`. The file contains the fully-resolved transitive
// closure of all configurations, making it a safe static lockfile for lockfile-static analysis.
//
// File format:
//
//	# comment
//	groupId:artifactId:version=config1,config2,...
//	empty=
//
// Configuration → DepType mapping:
//   - any configuration containing "test" (case-insensitive) → "test"
//   - all others (compileClasspath, runtimeClasspath, api, implementation,
//     runtimeOnly, …) → "runtime"
//
// When the same coordinate appears in both runtime and test configurations (e.g.
// "runtimeClasspath,testCompileClasspath"), "runtime" wins over "test" — consistent
// with mergeDepType semantics and the "unknown ≠ safe" invariant: we must not
// suppress a runtime advisory by accidentally tagging it as test-only.
//
// Returns:
//   - (nil, false, nil) when gradle.lockfile is absent (no error: caller decides next step).
//   - (deps, true, nil) when gradle.lockfile is present and parseable (even if empty).
//   - Malformed dep lines are skipped silently; the lockfile is still considered
//     complete if the file itself is parseable (gradle.lockfile is machine-generated).
func parseGradleLockfile(root string) ([]ResolvedDep, bool, error) {
	lockPath := filepath.Join(root, "gradle.lockfile")
	f, err := os.Open(lockPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Absent lockfile is not an error; caller can try pom.xml next.
			return nil, false, nil
		}
		return nil, false, err
	}
	defer func() { _ = f.Close() }()

	var deps []ResolvedDep

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comment lines and blank lines.
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// "empty=" is the sentinel for "no locked deps" — valid, skip.
		if line == "empty=" {
			continue
		}

		// Format: groupId:artifactId:version=config1,config2,...
		// Split on "=" first to separate the coordinate from the configurations.
		eqIdx := strings.Index(line, "=")
		if eqIdx < 0 {
			// Malformed line: no "=" separator; skip.
			continue
		}
		coordinate := line[:eqIdx]
		configPart := line[eqIdx+1:]

		// The coordinate must have exactly two ":" separators: group:artifact:version.
		parts := strings.SplitN(coordinate, ":", 3)
		if len(parts) != 3 {
			// Malformed coordinate (too few or too many segments); skip.
			continue
		}
		groupID := parts[0]
		artifactID := parts[1]
		version := parts[2]

		if groupID == "" || artifactID == "" || version == "" {
			// Any empty segment is invalid; skip.
			continue
		}

		// Compute DepType from the configuration list.
		// "runtime" wins over "test" (unknown ≠ safe: conservative default).
		depType := gradleConfigsToDepType(configPart)

		deps = append(deps, ResolvedDep{
			Name:    groupID + ":" + artifactID,
			Version: version,
			DepType: depType,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, false, err
	}

	// gradle.lockfile is present and parseable: the closure is complete (it is
	// machine-generated by Gradle's dependency locking feature and covers the
	// full transitive closure of all enabled configurations).
	return deps, true, nil
}

// gradleConfigsToDepType maps a comma-separated Gradle configuration list to a
// DepType string. "runtime" wins over "test": if any configuration is a runtime
// configuration, the dep is tagged runtime regardless of test configurations also
// being present.
//
// Conservative classification: anything not clearly "test-only" is tagged "runtime".
// This matches the "unknown ≠ safe" invariant — we must not suppress a runtime
// advisory by accidentally tagging it as test-only.
//
// Known runtime configurations: compileClasspath, runtimeClasspath, api,
// implementation, runtimeOnly, compile (legacy), runtime (legacy), provided.
// Known test configurations: testCompileClasspath, testRuntimeClasspath,
// testImplementation, testRuntimeOnly, testCompile (legacy), testRuntime (legacy).
// Integration-test configurations: integrationTestCompileClasspath,
// integrationTestRuntimeClasspath, functionalTestImplementation, etc.
//
// Classification uses isGradleTestConfig for word-boundary-aware detection:
// "test" is recognised only at a camelCase word boundary (start of name or
// after an uppercase letter), not as an arbitrary substring. This prevents
// false positives for config names like "attestationClasspath" or
// "contextClasspath" where "test" appears mid-word and is not semantically
// test-related. False negatives (unknown → runtime) are safer than false
// positives (unknown → test) per the "unknown ≠ safe" invariant.
func gradleConfigsToDepType(configPart string) string {
	if configPart == "" {
		// No configurations: unknown → runtime (conservative).
		return "runtime"
	}
	configs := strings.Split(configPart, ",")
	hasRuntime := false
	hasTestOnly := true

	for _, cfg := range configs {
		cfg = strings.TrimSpace(cfg)
		if cfg == "" {
			continue
		}
		if isGradleTestConfig(cfg) {
			// This configuration is test-related.
			continue
		}
		// Non-test configuration found → at least one runtime classification.
		hasRuntime = true
		hasTestOnly = false
	}

	if hasRuntime {
		return "runtime"
	}
	if hasTestOnly {
		return "test"
	}
	// All configs were empty strings (unusual); default to runtime.
	return "runtime"
}

// isGradleTestConfig reports whether cfg is a Gradle test configuration using
// word-boundary-aware matching. It recognises:
//   - Configs that start with "test" (case-insensitive): testCompileClasspath,
//     testRuntimeClasspath, testImplementation, testRuntimeOnly, etc.
//   - Configs that contain "Test" at a camelCase word start: integrationTestRuntime,
//     functionalTestCompileClasspath, smokeTestImplementation, etc.
//   - Configs that contain "TEST" (all-caps variant of the above).
//
// It does NOT match "test" as an arbitrary lowercase substring to avoid
// false positives for names like "attestationClasspath" or "contextClasspath",
// where "test" appears mid-word and is unrelated to testing.
func isGradleTestConfig(cfg string) bool {
	return strings.HasPrefix(strings.ToLower(cfg), "test") ||
		strings.Contains(cfg, "Test") ||
		strings.Contains(cfg, "TEST")
}

// ── pom.xml static parser ─────────────────────────────────────────────────────

// pomProject is the minimal XML schema for Maven pom.xml used by parsePomXML.
// Only the fields needed for dependency resolution are declared; all others are
// silently ignored by encoding/xml. The struct tags use local names without a
// namespace: Go's encoding/xml matches a tag with no namespace URI against elements
// in ANY namespace (Space=="" is a wildcard), so this works for both namespace-
// qualified pom.xml files (xmlns="http://maven.apache.org/POM/4.0.0") and bare
// pom.xml files without a default namespace declaration.
type pomProject struct {
	XMLName      xml.Name       `xml:"project"`
	Dependencies pomDepSection  `xml:"dependencies"`
	// DependencyManagement carries managed versions for BOM-style projects.
	// Entries here are NOT emitted as actual deps; they are used only to resolve
	// the version of a dep in <dependencies> that has no explicit <version>.
	DependencyManagement struct {
		Dependencies pomDepSection `xml:"dependencies"`
	} `xml:"dependencyManagement"`
}

// pomDepSection wraps the <dependencies> element and its <dependency> children.
type pomDepSection struct {
	Dependency []pomXMLDep `xml:"dependency"`
}

// pomXMLDep is one <dependency> element inside a <dependencies> block.
type pomXMLDep struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
	Optional   string `xml:"optional"`
}

// parsePomXML reads the pom.xml at root/pom.xml and returns the directly
// declared dependencies that have resolvable (concrete literal) versions.
//
// Resolution rules:
//   - Only <dependencies> under the top-level <project> are emitted as deps.
//     <dependencies> inside <dependencyManagement>, <profile>, or any other
//     nested element are NOT emitted as deps.
//   - <dependencyManagement> entries serve as a version source: if a dep in
//     <dependencies> has no explicit <version>, this function looks up a version
//     in <dependencyManagement> with the same groupId:artifactId. If the managed
//     version is a concrete literal, it is used; otherwise the dep is undecidable.
//   - Versions that are property references (${...}), absent and not found in
//     dependencyManagement, or otherwise non-literal → the dep is skipped AND
//     not emitted. "unknown ≠ safe".
//   - Transitives are NEVER included — they require running `mvn help:effective-pom`
//     (ACE risk on untrusted repos). A project vulnerable only through a transitive
//     dep would produce zero findings and exit 0 — a false-clean.
//
// complete is ALWAYS false: pom.xml cannot represent the full transitive closure.
// The caller marks the scan incomplete (exit 3) so a pom.xml-only project with
// no DIRECT-dep vulnerabilities never exits 0 (unknown ≠ safe for transitives).
//
// Returns:
//   - (nil, false, nil) when pom.xml is absent.
//   - (nil, false, nil) when pom.xml has no <dependencies> section (or they are all
//     malformed / undecidable): degrade to incomplete.
//   - (deps, false, nil) when at least one direct dep has a concrete literal version.
//     Undecidable-version deps are skipped; the rest are returned for OSV query.
//   - (nil, false, nil) on XML parse failure: degrade to incomplete rather than abort.
func parsePomXML(root string) ([]ResolvedDep, bool, error) {
	pomPath := filepath.Join(root, "pom.xml")
	f, err := os.Open(pomPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	defer func() { _ = f.Close() }()

	var proj pomProject
	if decErr := xml.NewDecoder(f).Decode(&proj); decErr != nil {
		// Malformed pom.xml: degrade gracefully to incomplete, not an error abort.
		return nil, false, nil
	}

	directDeps := proj.Dependencies.Dependency
	if len(directDeps) == 0 {
		// No <dependencies> declared. Cannot confirm the project has no deps without
		// running mvn (parent POM or BOM imports might contribute transitives).
		return nil, false, nil
	}

	// Build a version lookup from <dependencyManagement> to fill in missing versions.
	// Only concrete literal versions (not ${...}) are indexed.
	mgmtVersion := make(map[string]string, len(proj.DependencyManagement.Dependencies.Dependency))
	for _, d := range proj.DependencyManagement.Dependencies.Dependency {
		key := d.GroupID + ":" + d.ArtifactID
		v := strings.TrimSpace(d.Version)
		if v != "" && !strings.HasPrefix(v, "${") {
			mgmtVersion[key] = v
		}
	}

	var resolved []ResolvedDep

	for _, d := range directDeps {
		if d.GroupID == "" || d.ArtifactID == "" {
			// Malformed entry (missing coordinates); skip silently.
			continue
		}

		version := strings.TrimSpace(d.Version)
		if version == "" {
			// No explicit version: try dependencyManagement as a fallback.
			key := d.GroupID + ":" + d.ArtifactID
			if v, ok := mgmtVersion[key]; ok {
				version = v
			}
		}

		if version == "" || strings.HasPrefix(version, "${") {
			// Undecidable: property reference, inherited from a parent POM,
			// or absent and not found in dependencyManagement. Skip this dep
			// silently; the caller already receives complete=false so the scan
			// is correctly marked incomplete (unknown ≠ safe).
			continue
		}

		resolved = append(resolved, ResolvedDep{
			Name:    d.GroupID + ":" + d.ArtifactID,
			Version: version,
			DepType: pomScopeToDepType(d.Scope, d.Optional),
		})
	}

	if len(resolved) == 0 {
		// All deps had undecidable versions or malformed coordinates.
		return nil, false, nil
	}

	// complete is ALWAYS false for the pom.xml path: the returned closure covers
	// only direct declared deps. Transitives are unknown (require mvn; ACE risk).
	// The caller must mark the scan incomplete so a project whose only vulnerability
	// lives in a transitive dep never exits 0 (false-clean). "unknown ≠ safe".
	return resolved, false, nil
}

// pomScopeToDepType maps a Maven dependency scope and optional flag to a DepType
// string for the advisory gate.
//
// Scope mappings (Maven 3 semantics):
//   - "test"     → "dev"     (test classpath only; not in production runtime)
//   - "provided" → "dev"     (expected from container/JDK at runtime; excluded from deployment artifact)
//   - "compile"  → "runtime" (default; in all classpaths)
//   - "runtime"  → "runtime" (runtime + test classpaths; not compile)
//   - "system"   → "runtime" (conservative: treated same as compile for gating)
//   - absent     → "runtime" (conservative: unknown scope = assume runtime)
//
// <optional>true</optional> → "dev": optional deps are excluded from dependents'
// transitive classpaths and are therefore not on the production runtime path of
// consuming projects.
//
// Conservative default: unknown/absent scope → "runtime" (unknown ≠ safe: we
// must not suppress a potentially runtime-reachable advisory).
func pomScopeToDepType(scope, optional string) string {
	if strings.EqualFold(strings.TrimSpace(optional), "true") {
		return "dev"
	}
	switch strings.ToLower(strings.TrimSpace(scope)) {
	case "test", "provided":
		return "dev"
	default: // "compile", "runtime", "system", "" (absent) → conservative runtime
		return "runtime"
	}
}
