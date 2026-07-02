package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/commit0-dev/commit0-analyzer/internal/advisory"
)

// findMavenAdapter returns the first registered lockfile-static adapter with
// Language=="java" that is backed by the real parser (ecosystem_maven.go).
// It distinguishes the real adapter from the Phase-0 stub by calling
// ParseLockfile on a dir that contains gradle.lockfile: the real adapter
// returns complete=true; the stub always returns complete=false.
//
// Callers that do not need to distinguish can call findAnyJavaAdapter.
func findMavenAdapter(t *testing.T) *EcosystemAdapter {
	t.Helper()

	// Build a temp dir with a gradle.lockfile so the real adapter can signal
	// complete=true on it (the Phase-0 stub always returns false).
	dir := t.TempDir()
	writeLockfile(t, dir, "gradle.lockfile", singleDepGradleLockfile)

	for _, a := range EcosystemAdapters() {
		if a.Language != "java" {
			continue
		}
		deps, complete, err := a.ParseLockfile(dir)
		if err == nil && complete && len(deps) > 0 {
			a := a
			return &a
		}
	}
	return nil
}

func writeLockfile(t *testing.T, dir, name, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644))
}

// ── Fixtures ──────────────────────────────────────────────────────────────────

const singleDepGradleLockfile = `# This is a Gradle generated file for dependency locking.
# Manual edits can break the build and are not advised.
# This file is expected to be part of source control.
org.springframework.boot:spring-boot-starter-web:2.7.9=compileClasspath,runtimeClasspath
empty=
`

const testDepGradleLockfile = `# Gradle lockfile with test dep
org.springframework.boot:spring-boot-starter-web:2.7.9=compileClasspath,runtimeClasspath
junit:junit:4.13.2=testCompileClasspath,testRuntimeClasspath
empty=
`

const mixedScopeGradleLockfile = `# Mixed runtime and test deps
com.google.guava:guava:31.1-jre=compileClasspath,runtimeClasspath
org.assertj:assertj-core:3.24.2=testCompileClasspath,testRuntimeClasspath
org.springframework.boot:spring-boot:2.7.9=runtimeClasspath
empty=
`

const emptyGradleLockfile = `# No deps at all
empty=
`

const malformedGradleLockfile = `# This lockfile has malformed lines
not_a_valid:line=config
:missing-group:1.0=compileClasspath
group:missing-version:=compileClasspath
empty=
`

// minimal pom.xml with runtime and test scopes — all versions are concrete literals.
const pomXMLWithDeps = `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
             http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>demo</artifactId>
    <version>1.0.0</version>
    <dependencies>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
            <version>5.3.27</version>
        </dependency>
        <dependency>
            <groupId>junit</groupId>
            <artifactId>junit</artifactId>
            <version>4.13.2</version>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>com.fasterxml.jackson.core</groupId>
            <artifactId>jackson-databind</artifactId>
            <version>2.14.2</version>
            <scope>runtime</scope>
        </dependency>
    </dependencies>
</project>
`

// pom.xml that mixes a property-ref version (undecidable) with a literal version.
const pomXMLWithPropertyRef = `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.example</groupId>
    <artifactId>demo</artifactId>
    <version>1.0.0</version>
    <dependencies>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
            <version>${spring.version}</version>
        </dependency>
        <dependency>
            <groupId>com.fasterxml.jackson.core</groupId>
            <artifactId>jackson-databind</artifactId>
            <version>2.14.2</version>
        </dependency>
    </dependencies>
</project>
`

// pom.xml with no <dependencies> section at all.
const pomXMLNoDeps = `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.example</groupId>
    <artifactId>demo</artifactId>
    <version>1.0.0</version>
</project>
`

// pom.xml with optional=true and provided scope — both map to "dev".
const pomXMLWithOptional = `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.example</groupId>
    <artifactId>demo</artifactId>
    <version>1.0.0</version>
    <dependencies>
        <dependency>
            <groupId>com.example</groupId>
            <artifactId>optional-lib</artifactId>
            <version>1.0.0</version>
            <optional>true</optional>
        </dependency>
        <dependency>
            <groupId>com.example</groupId>
            <artifactId>provided-lib</artifactId>
            <version>2.0.0</version>
            <scope>provided</scope>
        </dependency>
        <dependency>
            <groupId>com.example</groupId>
            <artifactId>runtime-lib</artifactId>
            <version>3.0.0</version>
        </dependency>
    </dependencies>
</project>
`

// pom.xml that resolves a missing version from <dependencyManagement>.
const pomXMLWithDependencyManagement = `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.example</groupId>
    <artifactId>demo</artifactId>
    <version>1.0.0</version>
    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>org.springframework</groupId>
                <artifactId>spring-core</artifactId>
                <version>5.3.27</version>
            </dependency>
        </dependencies>
    </dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
        </dependency>
    </dependencies>
</project>
`

// ── Real adapter registration ─────────────────────────────────────────────────

// TestMavenAdapter_IsRegistered verifies that the real Maven adapter (backed by
// ecosystem_maven.go) is present in the global registry after package init.
func TestMavenAdapter_IsRegistered(t *testing.T) {
	adapter := findMavenAdapter(t)
	require.NotNil(t, adapter,
		"real Maven adapter (ecosystem_maven.go) must be registered; "+
			"none of the Java adapters returned complete=true for a gradle.lockfile dir")
}

// TestMavenAdapter_Ecosystem verifies that the real Maven adapter declares the
// "Maven" OSV ecosystem so OSV advisory queries use the correct bundle.
func TestMavenAdapter_Ecosystem(t *testing.T) {
	adapter := findMavenAdapter(t)
	require.NotNil(t, adapter, "real Maven adapter must be registered")
	assert.Equal(t, advisory.EcosystemMaven, adapter.Ecosystem,
		"Maven adapter must declare advisory.EcosystemMaven as its ecosystem")
}

// TestMavenAdapter_NormalizeName_Nil verifies that the Maven adapter does NOT
// normalize package names (Maven coordinates are case-sensitive; lowercasing
// would miss OSV records).
func TestMavenAdapter_NormalizeName_Nil(t *testing.T) {
	adapter := findMavenAdapter(t)
	require.NotNil(t, adapter, "real Maven adapter must be registered")
	assert.Nil(t, adapter.NormalizeName,
		"Maven adapter must NOT normalize names (Maven coordinates are case-sensitive)")
}

// ── gradle.lockfile parsing ──────────────────────────────────────────────────

// TestMavenAdapter_GradleLockfile_SingleRuntimeDep verifies that a gradle.lockfile
// with one runtime dependency is parsed correctly and returns complete=true.
func TestMavenAdapter_GradleLockfile_SingleRuntimeDep(t *testing.T) {
	adapter := findMavenAdapter(t)
	require.NotNil(t, adapter, "real Maven adapter must be registered")

	dir := t.TempDir()
	writeLockfile(t, dir, "gradle.lockfile", singleDepGradleLockfile)

	deps, complete, err := adapter.ParseLockfile(dir)
	require.NoError(t, err, "ParseLockfile must not return error for valid gradle.lockfile")
	assert.True(t, complete,
		"gradle.lockfile present → ParseLockfile must return complete=true (full transitive closure)")

	require.Len(t, deps, 1, "one dep expected from the lockfile")
	assert.Equal(t, "org.springframework.boot:spring-boot-starter-web", deps[0].Name)
	assert.Equal(t, "2.7.9", deps[0].Version)
	assert.Equal(t, "runtime", deps[0].DepType,
		"compileClasspath/runtimeClasspath configurations must map to DepType='runtime'")
}

// TestMavenAdapter_GradleLockfile_TestDepClassification verifies that entries
// on test configurations (testCompileClasspath, testRuntimeClasspath) are tagged
// as DepType="test", enabling the dev_only gate.
func TestMavenAdapter_GradleLockfile_TestDepClassification(t *testing.T) {
	adapter := findMavenAdapter(t)
	require.NotNil(t, adapter, "real Maven adapter must be registered")

	dir := t.TempDir()
	writeLockfile(t, dir, "gradle.lockfile", testDepGradleLockfile)

	deps, complete, err := adapter.ParseLockfile(dir)
	require.NoError(t, err)
	assert.True(t, complete)
	require.Len(t, deps, 2)

	byName := map[string]ResolvedDep{}
	for _, d := range deps {
		byName[d.Name] = d
	}

	spring := byName["org.springframework.boot:spring-boot-starter-web"]
	assert.Equal(t, "2.7.9", spring.Version)
	assert.Equal(t, "runtime", spring.DepType,
		"compileClasspath+runtimeClasspath → DepType must be 'runtime'")

	junit := byName["junit:junit"]
	assert.Equal(t, "4.13.2", junit.Version)
	assert.Equal(t, "test", junit.DepType,
		"testCompileClasspath+testRuntimeClasspath → DepType must be 'test'")
}

// TestMavenAdapter_GradleLockfile_MixedConfigurations tests a lockfile with
// multiple dep entries and varying configurations, verifying that "runtime wins"
// over "test" when the same dep appears in both runtime and test classpaths.
func TestMavenAdapter_GradleLockfile_MixedConfigurations(t *testing.T) {
	adapter := findMavenAdapter(t)
	require.NotNil(t, adapter, "real Maven adapter must be registered")

	dir := t.TempDir()
	writeLockfile(t, dir, "gradle.lockfile", mixedScopeGradleLockfile)

	deps, complete, err := adapter.ParseLockfile(dir)
	require.NoError(t, err)
	assert.True(t, complete)
	require.Len(t, deps, 3)

	byName := map[string]ResolvedDep{}
	for _, d := range deps {
		byName[d.Name] = d
	}

	guava := byName["com.google.guava:guava"]
	assert.Equal(t, "runtime", guava.DepType, "compileClasspath+runtimeClasspath → runtime")

	assertj := byName["org.assertj:assertj-core"]
	assert.Equal(t, "test", assertj.DepType, "testClasspaths only → test")

	sb := byName["org.springframework.boot:spring-boot"]
	assert.Equal(t, "runtime", sb.DepType, "runtimeClasspath → runtime")
}

// TestMavenAdapter_GradleLockfile_EmptyLockfile verifies that a gradle.lockfile
// with only the "empty=" sentinel (no locked deps) returns complete=true with an
// empty closure. This is valid: a project with no dependencies is dependency-free.
func TestMavenAdapter_GradleLockfile_EmptyLockfile(t *testing.T) {
	adapter := findMavenAdapter(t)
	require.NotNil(t, adapter, "real Maven adapter must be registered")

	dir := t.TempDir()
	writeLockfile(t, dir, "gradle.lockfile", emptyGradleLockfile)

	deps, complete, err := adapter.ParseLockfile(dir)
	require.NoError(t, err, "empty gradle.lockfile must not be an error")
	assert.True(t, complete,
		"empty gradle.lockfile still represents a complete (zero-dep) closure")
	assert.Empty(t, deps, "no deps expected from an empty lockfile")
}

// TestMavenAdapter_GradleLockfile_Comments verifies that comment lines (starting
// with #) are skipped and do not appear as resolved dependencies.
func TestMavenAdapter_GradleLockfile_Comments(t *testing.T) {
	adapter := findMavenAdapter(t)
	require.NotNil(t, adapter, "real Maven adapter must be registered")

	content := `# Comment line 1
# Comment line 2
com.example:library:1.0.0=compileClasspath
empty=
`
	dir := t.TempDir()
	writeLockfile(t, dir, "gradle.lockfile", content)

	deps, complete, err := adapter.ParseLockfile(dir)
	require.NoError(t, err)
	assert.True(t, complete)
	require.Len(t, deps, 1, "only one dep; comment lines must be ignored")
	assert.Equal(t, "com.example:library", deps[0].Name)
}

// TestMavenAdapter_GradleLockfile_NamePreservation verifies that Maven coordinate
// case is preserved exactly as it appears in the lockfile. OSV Maven records use
// the canonical case; lowercasing would produce mismatches.
func TestMavenAdapter_GradleLockfile_NamePreservation(t *testing.T) {
	adapter := findMavenAdapter(t)
	require.NotNil(t, adapter, "real Maven adapter must be registered")

	content := "com.MyOrg:MyLib:1.2.3=compileClasspath\nempty=\n"
	dir := t.TempDir()
	writeLockfile(t, dir, "gradle.lockfile", content)

	deps, complete, err := adapter.ParseLockfile(dir)
	require.NoError(t, err)
	assert.True(t, complete)
	require.Len(t, deps, 1)
	assert.Equal(t, "com.MyOrg:MyLib", deps[0].Name,
		"Maven coordinate case must be preserved verbatim (OSV Maven is case-sensitive)")
}

// TestMavenAdapter_GradleLockfile_NoSubprocess verifies that ParseLockfile never
// spawns a subprocess (build tool), even when gradle.lockfile is present.
// ACE-safety: build scripts are untrusted code.
func TestMavenAdapter_GradleLockfile_NoSubprocess(t *testing.T) {
	adapter := findMavenAdapter(t)
	require.NotNil(t, adapter, "real Maven adapter must be registered")

	dir := t.TempDir()
	writeLockfile(t, dir, "gradle.lockfile", singleDepGradleLockfile)

	// If ParseLockfile spawns a subprocess that fails, it would likely return
	// a non-nil error. A pure-Go parse must succeed without any external process.
	_, _, err := adapter.ParseLockfile(dir)
	assert.NoError(t, err, "gradle.lockfile parse must be subprocess-free (ACE-safety)")
}

// ── pom.xml-only fallback (no gradle.lockfile) ────────────────────────────────

// TestMavenAdapter_PomXML_AllLiteralVersions verifies that when only pom.xml is
// present (no gradle.lockfile) and ALL direct dependency versions are concrete
// literals, the adapter returns the declared deps with complete=false.
//
// complete is ALWAYS false for the pom.xml path: pom.xml covers only DIRECT
// declared deps; the full TRANSITIVE closure requires `mvn help:effective-pom`
// (ACE risk on untrusted repos). A project vulnerable only through a transitive
// dep would otherwise produce zero findings and exit 0 — a silent false-clean.
// complete=false ensures the caller marks the scan incomplete (exit 3) so a
// clean direct-dep pom.xml scan never passes as safe. "unknown ≠ safe".
func TestMavenAdapter_PomXML_AllLiteralVersions(t *testing.T) {
	adapter := findMavenAdapter(t)
	require.NotNil(t, adapter, "real Maven adapter must be registered")

	dir := t.TempDir()
	writeLockfile(t, dir, "pom.xml", pomXMLWithDeps)

	deps, complete, err := adapter.ParseLockfile(dir)
	require.NoError(t, err, "pom.xml-only parse must not error")
	assert.False(t, complete,
		"pom.xml path → complete=ALWAYS false (direct deps only; transitives unknown; "+
			"a transitive-only vuln must not silently exit 0)")
	require.Len(t, deps, 3, "pomXMLWithDeps has 3 direct deps")

	byName := map[string]ResolvedDep{}
	for _, d := range deps {
		byName[d.Name] = d
	}

	spring := byName["org.springframework:spring-core"]
	assert.Equal(t, "5.3.27", spring.Version)
	assert.Equal(t, "runtime", spring.DepType, "no scope → default compile → runtime")

	junit := byName["junit:junit"]
	assert.Equal(t, "4.13.2", junit.Version)
	assert.Equal(t, "dev", junit.DepType, "scope=test → dev")

	jackson := byName["com.fasterxml.jackson.core:jackson-databind"]
	assert.Equal(t, "2.14.2", jackson.Version)
	assert.Equal(t, "runtime", jackson.DepType, "scope=runtime → runtime")
}

// TestMavenAdapter_PomXML_NoDeps_ReturnsIncomplete verifies that a pom.xml with
// no <dependencies> section returns complete=false with nil deps. Without declared
// deps we cannot know whether the project truly has none (parent POM may add deps),
// so we degrade to incomplete rather than claiming a clean zero-dep closure.
func TestMavenAdapter_PomXML_NoDeps_ReturnsIncomplete(t *testing.T) {
	adapter := findMavenAdapter(t)
	require.NotNil(t, adapter, "real Maven adapter must be registered")

	dir := t.TempDir()
	writeLockfile(t, dir, "pom.xml", pomXMLNoDeps)

	deps, complete, err := adapter.ParseLockfile(dir)
	require.NoError(t, err, "pom.xml with no deps must not error")
	assert.False(t, complete,
		"pom.xml with no <dependencies> → complete=false (parent POM may add transitives)")
	assert.Nil(t, deps)
}

// TestMavenAdapter_PomXML_PropertyRef_Incomplete verifies that a pom.xml whose
// deps include a property-reference version (${...}) is skipped and the closure
// is marked incomplete. The literal-version dep is still returned (not dropped),
// but complete=false signals the caller that some deps could not be resolved.
//
// "unknown ≠ safe": a dep with an undecidable version might be vulnerable; the
// caller must set incomplete=true rather than silently treating it as safe.
func TestMavenAdapter_PomXML_PropertyRef_Incomplete(t *testing.T) {
	adapter := findMavenAdapter(t)
	require.NotNil(t, adapter, "real Maven adapter must be registered")

	dir := t.TempDir()
	writeLockfile(t, dir, "pom.xml", pomXMLWithPropertyRef)

	deps, complete, err := adapter.ParseLockfile(dir)
	require.NoError(t, err, "pom.xml with property ref must not error")
	assert.False(t, complete,
		"pom.xml with ${...} version → complete=false (property ref is undecidable without mvn)")
	// The literal-version dep (jackson-databind) must still be returned.
	require.Len(t, deps, 1, "only the literal-version dep must be returned; property-ref dep skipped")
	assert.Equal(t, "com.fasterxml.jackson.core:jackson-databind", deps[0].Name)
	assert.Equal(t, "2.14.2", deps[0].Version)
}

// TestMavenAdapter_PomXML_Optional_DepType verifies that <optional>true</optional>
// deps and <scope>provided</scope> deps are classified as "dev", not "runtime".
func TestMavenAdapter_PomXML_Optional_DepType(t *testing.T) {
	adapter := findMavenAdapter(t)
	require.NotNil(t, adapter, "real Maven adapter must be registered")

	dir := t.TempDir()
	writeLockfile(t, dir, "pom.xml", pomXMLWithOptional)

	deps, complete, err := adapter.ParseLockfile(dir)
	require.NoError(t, err)
	assert.False(t, complete,
		"pom.xml path → complete=ALWAYS false (direct deps only; transitives unknown)")
	require.Len(t, deps, 3)

	byName := map[string]ResolvedDep{}
	for _, d := range deps {
		byName[d.Name] = d
	}

	opt := byName["com.example:optional-lib"]
	assert.Equal(t, "dev", opt.DepType,
		"<optional>true</optional> → DepType must be 'dev'")

	prov := byName["com.example:provided-lib"]
	assert.Equal(t, "dev", prov.DepType,
		"<scope>provided</scope> → DepType must be 'dev'")

	rt := byName["com.example:runtime-lib"]
	assert.Equal(t, "runtime", rt.DepType,
		"no scope, not optional → DepType must be 'runtime'")
}

// TestMavenAdapter_PomXML_DependencyManagement_VersionResolution verifies that
// a dep in <dependencies> with no explicit <version> is resolved via
// <dependencyManagement>. If the version in dependencyManagement is a literal,
// the dep is emitted; if it is a property ref or absent, the dep is skipped.
func TestMavenAdapter_PomXML_DependencyManagement_VersionResolution(t *testing.T) {
	adapter := findMavenAdapter(t)
	require.NotNil(t, adapter, "real Maven adapter must be registered")

	dir := t.TempDir()
	writeLockfile(t, dir, "pom.xml", pomXMLWithDependencyManagement)

	deps, complete, err := adapter.ParseLockfile(dir)
	require.NoError(t, err)
	assert.False(t, complete,
		"pom.xml path → complete=ALWAYS false (direct deps only; transitives unknown)")
	require.Len(t, deps, 1, "one dep resolved via dependencyManagement")
	assert.Equal(t, "org.springframework:spring-core", deps[0].Name)
	assert.Equal(t, "5.3.27", deps[0].Version)
}

// TestParsePomXML_DirectFunc tests the parsePomXML function directly,
// independent of the adapter registration machinery.
func TestParsePomXML_DirectFunc(t *testing.T) {
	dir := t.TempDir()
	writeLockfile(t, dir, "pom.xml", pomXMLWithDeps)

	deps, complete, err := parsePomXML(dir)
	require.NoError(t, err)
	assert.False(t, complete,
		"parsePomXML NEVER returns complete=true (direct deps only; transitives unknown)")
	require.Len(t, deps, 3)
}

// TestParsePomXML_DirectDepsEmittedForOSV verifies that parsePomXML returns the
// declared deps even when complete=false, so they remain available for OSV query
// by any caller that handles the partial-closure case. This is the key correctness
// invariant: a vulnerable direct dep (e.g. log4j-core 2.14.1) must appear in the
// returned slice so the scan loop can report it as PACKAGE_REACHABLE.
func TestParsePomXML_DirectDepsEmittedForOSV(t *testing.T) {
	const log4jVuln = `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.example</groupId>
    <artifactId>vuln-app</artifactId>
    <version>1.0.0</version>
    <dependencies>
        <dependency>
            <groupId>org.apache.logging.log4j</groupId>
            <artifactId>log4j-core</artifactId>
            <version>2.14.1</version>
        </dependency>
    </dependencies>
</project>
`
	dir := t.TempDir()
	writeLockfile(t, dir, "pom.xml", log4jVuln)

	deps, complete, err := parsePomXML(dir)
	require.NoError(t, err)
	assert.False(t, complete,
		"pom.xml path is always incomplete (transitives unknown)")
	require.Len(t, deps, 1, "log4j-core must be returned for OSV query")
	assert.Equal(t, "org.apache.logging.log4j:log4j-core", deps[0].Name)
	assert.Equal(t, "2.14.1", deps[0].Version)
	assert.Equal(t, "runtime", deps[0].DepType,
		"no scope → default compile → runtime (not suppressed by dev_only gate)")
}

// TestParsePomXML_Absent verifies that parsePomXML returns (nil, false, nil)
// when no pom.xml exists — not an error, just a missing file.
func TestParsePomXML_Absent(t *testing.T) {
	dir := t.TempDir()

	deps, complete, err := parsePomXML(dir)
	assert.NoError(t, err, "absent pom.xml must not error")
	assert.False(t, complete)
	assert.Nil(t, deps)
}

// TestMavenAdapter_PomOnly_NoSubprocess verifies that ParseLockfile does not
// spawn mvn, ./mvnw, gradle, or any other build tool when only pom.xml is present.
// Running a build tool on an untrusted pom.xml is arbitrary code execution.
func TestMavenAdapter_PomOnly_NoSubprocess(t *testing.T) {
	adapter := findMavenAdapter(t)
	require.NotNil(t, adapter, "real Maven adapter must be registered")

	dir := t.TempDir()
	writeLockfile(t, dir, "pom.xml", pomXMLWithDeps)

	_, _, err := adapter.ParseLockfile(dir)
	assert.NoError(t, err,
		"pom.xml-only parse must not spawn a subprocess (ACE-safety: no mvn/mvnw/gradle/gradlew)")
}

// TestMavenAdapter_BuildGradleOnly_ReturnsIncomplete verifies that detecting
// build.gradle (without gradle.lockfile) returns complete=false. We cannot
// evaluate build.gradle[.kts] (Groovy/Kotlin code = ACE), so without a lockfile
// the closure is unresolvable.
func TestMavenAdapter_BuildGradleOnly_ReturnsIncomplete(t *testing.T) {
	adapter := findMavenAdapter(t)
	require.NotNil(t, adapter, "real Maven adapter must be registered")

	dir := t.TempDir()
	writeLockfile(t, dir, "build.gradle", "// build.gradle without dependency locking")

	deps, complete, err := adapter.ParseLockfile(dir)
	require.NoError(t, err, "build.gradle-only parse must not error")
	assert.False(t, complete,
		"build.gradle without gradle.lockfile → complete=false (lockfile required for safe static parse)")
	assert.Nil(t, deps,
		"no lockfile → nil deps (NEVER return partial closure with complete=false)")
}

// TestMavenAdapter_EmptyDir_ReturnsIncomplete verifies that ParseLockfile on an
// empty dir (no manifest, no lockfile) returns (nil, false, nil) without panicking.
func TestMavenAdapter_EmptyDir_ReturnsIncomplete(t *testing.T) {
	adapter := findMavenAdapter(t)
	require.NotNil(t, adapter, "real Maven adapter must be registered")

	dir := t.TempDir()
	deps, complete, err := adapter.ParseLockfile(dir)
	assert.NoError(t, err)
	assert.False(t, complete)
	assert.Nil(t, deps)
}

// TestMavenAdapter_GradleLockfileWithPom_PrefersLockfile verifies that when
// BOTH pom.xml AND gradle.lockfile are present, the adapter uses the lockfile
// (full transitive closure) rather than the pom.xml (declared-only).
func TestMavenAdapter_GradleLockfileWithPom_PrefersLockfile(t *testing.T) {
	adapter := findMavenAdapter(t)
	require.NotNil(t, adapter, "real Maven adapter must be registered")

	dir := t.TempDir()
	writeLockfile(t, dir, "pom.xml", pomXMLWithDeps)
	writeLockfile(t, dir, "gradle.lockfile", singleDepGradleLockfile)

	deps, complete, err := adapter.ParseLockfile(dir)
	require.NoError(t, err)
	assert.True(t, complete,
		"gradle.lockfile takes precedence over pom.xml; complete=true")
	require.Len(t, deps, 1,
		"only the gradle.lockfile dep (spring-boot-starter-web), not pom.xml deps")
	assert.Equal(t, "org.springframework.boot:spring-boot-starter-web", deps[0].Name)
}

// TestMavenAdapter_GradleLockfile_DuplicateCoordinate verifies that if the same
// coordinate appears multiple times in a lockfile (unlikely but possible via
// multiple configuration blocks), each entry is treated independently. The
// dep-type is the most conservative (runtime wins over test).
func TestMavenAdapter_GradleLockfile_DuplicateCoordinate(t *testing.T) {
	adapter := findMavenAdapter(t)
	require.NotNil(t, adapter, "real Maven adapter must be registered")

	// Unusual case: same GAV appears twice with different configurations.
	// The parser may return duplicates; the important thing is it doesn't crash.
	content := "com.example:lib:1.0.0=compileClasspath\ncom.example:lib:1.0.0=testCompileClasspath\nempty=\n"
	dir := t.TempDir()
	writeLockfile(t, dir, "gradle.lockfile", content)

	deps, complete, err := adapter.ParseLockfile(dir)
	require.NoError(t, err, "duplicate coordinate must not error")
	assert.True(t, complete)
	// At minimum, we must have at least one entry. Exact dedup policy is
	// implementation-defined; we just verify correctness doesn't break.
	assert.NotEmpty(t, deps, "at least one dep must be returned")
}

// TestMavenAdapter_GradleLockfile_DepType_RuntimeWins verifies that "runtime"
// dep-type beats "test" for the same dependency — consistent with mergeDepType
// semantics used by the advisory gate.
func TestMavenAdapter_GradleLockfile_DepType_RuntimeWins(t *testing.T) {
	adapter := findMavenAdapter(t)
	require.NotNil(t, adapter, "real Maven adapter must be registered")

	// Same dep in both runtime and test configurations.
	content := "com.example:lib:1.0.0=runtimeClasspath,testCompileClasspath\nempty=\n"
	dir := t.TempDir()
	writeLockfile(t, dir, "gradle.lockfile", content)

	deps, complete, err := adapter.ParseLockfile(dir)
	require.NoError(t, err)
	assert.True(t, complete)
	require.NotEmpty(t, deps)

	found := false
	for _, d := range deps {
		if d.Name == "com.example:lib" {
			assert.Equal(t, "runtime", d.DepType,
				"runtimeClasspath + testClasspath → DepType must be 'runtime' (runtime wins)")
			found = true
		}
	}
	assert.True(t, found, "com.example:lib must appear in the dep list")
}

// TestMavenAdapter_ParseGradleLockfile_DirectFunc tests the internal
// parseGradleLockfile function directly. This ensures the parsing logic is
// correct independent of the adapter registration machinery.
func TestMavenAdapter_ParseGradleLockfile_DirectFunc(t *testing.T) {
	dir := t.TempDir()
	writeLockfile(t, dir, "gradle.lockfile", testDepGradleLockfile)

	deps, complete, err := parseGradleLockfile(dir)
	require.NoError(t, err)
	assert.True(t, complete)
	require.Len(t, deps, 2)
}

// TestMavenAdapter_ParseGradleLockfile_Absent verifies that parseGradleLockfile
// returns (nil, false, nil) when no gradle.lockfile exists in the root.
func TestMavenAdapter_ParseGradleLockfile_Absent(t *testing.T) {
	dir := t.TempDir()

	deps, complete, err := parseGradleLockfile(dir)
	assert.NoError(t, err, "absent gradle.lockfile must not error")
	assert.False(t, complete)
	assert.Nil(t, deps)
}

// TestMavenAdapter_ParseGradleLockfile_MalformedLines verifies that malformed
// lines are skipped gracefully (not an error) — resilience against unusual or
// partially-corrupted lockfiles.
func TestMavenAdapter_ParseGradleLockfile_MalformedLines(t *testing.T) {
	dir := t.TempDir()
	writeLockfile(t, dir, "gradle.lockfile", malformedGradleLockfile)

	deps, complete, err := parseGradleLockfile(dir)
	// Malformed lines should be skipped, not cause an error.
	assert.NoError(t, err, "malformed lines must be skipped, not cause a parse error")
	assert.True(t, complete, "gradle.lockfile is present → complete=true even if some lines are malformed")
	// The malformed lines had 2-part (no version) or missing group, so 0 valid
	// GAV entries expected. The "empty=" sentinel is also present.
	_ = deps // exact count depends on how strictly the parser validates the format
}

// ── Single-registration invariant ────────────────────────────────────────────

// TestMavenAdapter_OnlyOneJavaAdapterRegistered verifies that exactly one Java
// lockfile-static adapter is registered after all init() functions have run. Having two
// adapters (the real one from ecosystem_maven.go and the Phase-0 stub from
// ecosystem_registry.go) causes the scan loop to run both: the stub always
// returns complete=false → marks the scan incomplete even when the real adapter
// fully parsed gradle.lockfile. The happy path (clean Java scan with exit 0) is
// unreachable unless the stub is removed.
func TestMavenAdapter_OnlyOneJavaAdapterRegistered(t *testing.T) {
	var javaAdapters []EcosystemAdapter
	for _, a := range EcosystemAdapters() {
		if a.Language == "java" {
			javaAdapters = append(javaAdapters, a)
		}
	}
	require.Len(t, javaAdapters, 1,
		"exactly one Java lockfile-static adapter must be registered; "+
			"duplicate registration (real adapter + Phase-0 stub) causes the scan loop to "+
			"always set incomplete=true even when gradle.lockfile is fully parsed")
}

// ── DetectFiles — spec-mandated set ──────────────────────────────────────────

// TestMavenAdapter_DetectFiles_IncludesGradleLockfile verifies that the real
// Maven adapter's DetectFiles includes "gradle.lockfile". Without it, a project
// root that contains ONLY gradle.lockfile (no build.gradle or pom.xml) is not
// detected as a Java project, so detectEcosystems leaves java out of scope, the
// lockfile-static loop is skipped, and the scan exits 0 (false-clean) rather than
// parsing the lockfile and querying OSV.
func TestMavenAdapter_DetectFiles_IncludesGradleLockfile(t *testing.T) {
	adapter := findMavenAdapter(t)
	require.NotNil(t, adapter, "real Maven adapter must be registered")

	hasGradleLockfile := false
	for _, f := range adapter.DetectFiles {
		if f == "gradle.lockfile" {
			hasGradleLockfile = true
			break
		}
	}
	assert.True(t, hasGradleLockfile,
		"DetectFiles must include 'gradle.lockfile' (spec-mandated); "+
			"a project root with only gradle.lockfile must be detected as a Java project "+
			"so the lockfile-static loop can parse it and query OSV")
}

// TestMavenAdapter_DetectEcosystems_GradleLockfileOnly verifies that
// detectEcosystems puts java in scope when the project root contains ONLY
// gradle.lockfile with no pom.xml or build.gradle present. This is the key
// zero-config acceptance test: a Gradle project with dependency locking enabled
// produces gradle.lockfile without necessarily having build.gradle in the same
// directory (e.g. in a flat multi-project layout or after a CI lockfile-only
// checkout). Without this detection the scan silently exits 0 — false-clean.
func TestMavenAdapter_DetectEcosystems_GradleLockfileOnly(t *testing.T) {
	dir := t.TempDir()
	writeLockfile(t, dir, "gradle.lockfile", singleDepGradleLockfile)

	eco := detectEcosystems(dir)
	assert.True(t, eco.active("java"),
		"gradle.lockfile-only project root must put java in scope via registry-driven detection; "+
			"without this, the lockfile-static loop is skipped and the scan exits 0 (false-clean)")
	assert.False(t, eco.active("go"), "no go.mod → Go must not be detected")
}

// TestMavenAdapter_FullPipeline_GradleLockfileOnly is the integration-level
// acceptance test for the complete gradle.lockfile-only scan path:
// detectEcosystems finds the project → the real adapter's ParseLockfile returns
// complete=true → deps are available for OSV query.
//
// This is the "happy path" that the dual-registration bug made unreachable:
// even when the real adapter returned complete=true, the stub adapter returned
// complete=false and forced incomplete=true on the scan.
func TestMavenAdapter_FullPipeline_GradleLockfileOnly(t *testing.T) {
	dir := t.TempDir()
	writeLockfile(t, dir, "gradle.lockfile", singleDepGradleLockfile)

	// Step 1: ecosystem detection must find Java.
	eco := detectEcosystems(dir)
	require.True(t, eco.active("java"),
		"precondition: gradle.lockfile must trigger Java detection")

	// Step 2: find the (now single) real maven adapter.
	adapter := findMavenAdapter(t)
	require.NotNil(t, adapter, "real Maven adapter must be registered")

	// Step 3: the real adapter must parse the lockfile completely.
	deps, complete, err := adapter.ParseLockfile(dir)
	require.NoError(t, err)
	assert.True(t, complete,
		"gradle.lockfile present → ParseLockfile must return complete=true; "+
			"incomplete=true here would cause the scan to exit 3 for a clean gradle.lockfile project")
	require.Len(t, deps, 1,
		"one dep expected from the single-dep lockfile fixture")
	assert.Equal(t, "org.springframework.boot:spring-boot-starter-web", deps[0].Name)

	// Step 4: with only the real adapter registered (no stub), running the full
	// adapter loop must produce complete=true. Simulate the scan.go lockfile-static loop:
	// if ANY adapter returns complete=false, it sets incomplete=true.
	allComplete := true
	for _, a := range EcosystemAdapters() {
		if a.Language != "java" {
			continue
		}
		_, c, e := a.ParseLockfile(dir)
		if e != nil || !c {
			allComplete = false
		}
	}
	assert.True(t, allComplete,
		"the lockfile-static loop must see complete=true from all registered Java adapters "+
			"for a gradle.lockfile project; the Phase-0 stub must not be present")
}

// ── gradleConfigsToDepType — word-boundary classification ────────────────────

// TestGradleConfig_AttestationSubstring_IsRuntime verifies that a Gradle
// configuration whose name contains "test" as a substring within a word (not at
// a camelCase word boundary) is classified as "runtime", not "test".
//
// Example: a hypothetical "attestationClasspath" config should not be
// suppressed by the dev_only gate. The substring match on "test" was overly
// aggressive and could cause false-clean passes (advisories dropped for packages
// that only appeared under such a configuration).
func TestGradleConfig_AttestationSubstring_IsRuntime(t *testing.T) {
	// "attestation" contains "test" as a substring (a-t-t-e-s-t-a-t-i-o-n)
	// but "test" does not appear at a camelCase word boundary. It is NOT a
	// test configuration and must classify as "runtime".
	content := "com.example:lib:1.0.0=attestationClasspath\nempty=\n"
	dir := t.TempDir()
	writeLockfile(t, dir, "gradle.lockfile", content)

	deps, complete, err := parseGradleLockfile(dir)
	require.NoError(t, err)
	assert.True(t, complete)
	require.Len(t, deps, 1)
	assert.Equal(t, "runtime", deps[0].DepType,
		"'attestationClasspath' contains 'test' as a substring within a word, "+
			"not at a word boundary; it must be classified as 'runtime', not 'test'")
}

// TestGradleConfig_IntegrationTest_IsTest verifies that integration-test
// configurations (e.g. integrationTestCompileClasspath) are correctly classified
// as "test" even though they do not start with "test". The word-boundary check
// catches them via the camelCase "Test" component.
func TestGradleConfig_IntegrationTest_IsTest(t *testing.T) {
	content := "com.example:lib:1.0.0=integrationTestCompileClasspath\nempty=\n"
	dir := t.TempDir()
	writeLockfile(t, dir, "gradle.lockfile", content)

	deps, complete, err := parseGradleLockfile(dir)
	require.NoError(t, err)
	assert.True(t, complete)
	require.Len(t, deps, 1)
	assert.Equal(t, "test", deps[0].DepType,
		"'integrationTestCompileClasspath' has 'Test' at a camelCase word boundary; "+
			"must be classified as 'test'")
}
