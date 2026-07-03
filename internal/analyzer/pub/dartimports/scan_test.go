package dartimports

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
)

func pkgs(t *testing.T, src string) []string {
	t.Helper()
	got := ScanSource([]byte(src)).ImportPackages
	sort.Strings(got)
	return got
}

func TestPackageName(t *testing.T) {
	cases := []struct {
		uri  string
		name string
		ok   bool
	}{
		{"package:foo/foo.dart", "foo", true},
		{"package:foo/src/deep/x.dart", "foo", true},
		{"package:flutter_bloc/flutter_bloc.dart", "flutter_bloc", true},
		{"package:foo", "foo", true}, // no slash: whole remainder is the name
		{"dart:async", "", false},
		{"dart:mirrors", "", false},
		{"src/relative.dart", "", false},
		{"foo.dart", "", false},
		{"package:", "", false},
		{"http://example.com/x.dart", "", false},
	}
	for _, c := range cases {
		name, ok := PackageName(c.uri)
		assert.Equal(t, c.ok, ok, c.uri)
		assert.Equal(t, c.name, name, c.uri)
	}
}

func TestScan_BasicImportsExportsAndDedup(t *testing.T) {
	src := `
library my.app;

import 'package:alpha/alpha.dart';
import 'package:beta/src/thing.dart' as b;
export 'package:gamma/gamma.dart' show Widget;
export 'src/local.dart';        // relative re-export → not a package
import 'dart:async';            // SDK → not a package
import 'relative/thing.dart';   // relative → not a package
import 'package:alpha/other.dart'; // duplicate package alpha
import "package:delta/delta.dart"; // double-quoted

void main() {}
`
	assert.Equal(t, []string{"alpha", "beta", "delta", "gamma"}, pkgs(t, src))
}

func TestScan_ConditionalImportUnionsBothBranches(t *testing.T) {
	// A conditional import names a literal package in every branch. Both must be
	// treated as used (sound over-approximation — never drop a branch).
	src := `import 'package:base/base.dart'
    if (dart.library.io) 'package:io_impl/io.dart'
    if (dart.library.html) 'package:web_impl/web.dart';`
	assert.Equal(t, []string{"base", "io_impl", "web_impl"}, pkgs(t, src))
}

func TestScan_DeferredImportNamesLiteralPackage(t *testing.T) {
	// Deferred loading still names a literal package: URI → counted as used, and
	// it is NOT a dynamism frontier (the URI is a compile-time literal).
	src := `import 'package:heavy/heavy.dart' deferred as heavy;`
	s := ScanSource([]byte(src))
	assert.Equal(t, []string{"heavy"}, s.ImportPackages)
	assert.False(t, s.MirrorsImport)
	assert.False(t, s.SpawnUri)
}

func TestScan_AdjacentStringConcatenationInURI(t *testing.T) {
	// Dart allows a directive URI to be several adjacent string literals; they
	// concatenate into one URI. Splitting them would under-count the real package
	// (a path to a false NOT_REACHABLE), so they must be joined.
	src := `import 'package:foo' '/foo.dart';
export 'package:' 'bar/bar.dart';`
	assert.Equal(t, []string{"bar", "foo"}, pkgs(t, src))
}

func TestScan_CommentsDoNotYieldImports(t *testing.T) {
	src := `
// import 'package:commented/commented.dart';
/* import 'package:block/block.dart';
   still a comment
   /* nested */ import 'package:nested/nested.dart'; */
import 'package:real/real.dart';
`
	assert.Equal(t, []string{"real"}, pkgs(t, src))
}

func TestScan_StringLiteralsDoNotYieldImports(t *testing.T) {
	src := `
final s = 'import \'package:fake/fake.dart\';';
final t = "package:alsofake/alsofake.dart";
final r = r'package:rawfake/rawfake.dart';
final triple = '''
  import 'package:triplefake/triplefake.dart';
''';
import 'package:genuine/genuine.dart';
`
	assert.Equal(t, []string{"genuine"}, pkgs(t, src))
}

func TestScan_KeywordAsIdentifierIsNotADirective(t *testing.T) {
	src := `
class C {
  void export(String path) {}     // method named export
  void run() {
    final import = 'package:x/x.dart'; // variable named import, assigned a string
    export('package:y/y.dart');        // call, arg is a string literal
  }
}
import 'package:onlyreal/onlyreal.dart';
`
	assert.Equal(t, []string{"onlyreal"}, pkgs(t, src))
}

func TestScan_PartOfIsNotAPartFile(t *testing.T) {
	src := `
part of my.library;
part of 'parent.dart';
part 'child.g.dart';
part 'other.dart';
`
	s := ScanSource([]byte(src))
	assert.ElementsMatch(t, []string{"child.g.dart", "other.dart"}, s.PartFiles)
	assert.Empty(t, s.ImportPackages)
}

func TestScan_MirrorsImportDetected(t *testing.T) {
	s := ScanSource([]byte(`import 'dart:mirrors';
import 'package:foo/foo.dart';`))
	assert.True(t, s.MirrorsImport)
	assert.Equal(t, []string{"foo"}, s.ImportPackages)
}

func TestScan_MirrorsInsideStringOrCommentDoesNotTrip(t *testing.T) {
	s := ScanSource([]byte(`
// import 'dart:mirrors';
final x = "dart:mirrors";
import 'package:foo/foo.dart';
`))
	assert.False(t, s.MirrorsImport)
}

func TestScan_SpawnUriDetected(t *testing.T) {
	s := ScanSource([]byte(`
import 'dart:isolate';
void go() async {
  await Isolate.spawnUri(Uri.parse('foo'), [], null);
}
`))
	assert.True(t, s.SpawnUri)
}

func TestScan_SpawnUriInStringInterpolationTrips(t *testing.T) {
	// The interpolation embeds a real call whose inner string reuses the outer
	// quote; a lexer that does not model ${...} would desync on the inner quote
	// and miss the call. It must be detected (a frontier miss is a false NR).
	s := ScanSource([]byte(`var s = "pre ${Isolate.spawnUri("u")} post";`))
	assert.True(t, s.SpawnUri)
}

func TestScan_SpawnUriInNestedInterpolationTrips(t *testing.T) {
	s := ScanSource([]byte(`var s = "a ${f("b ${Isolate.spawnUri("u")} c")} d";`))
	assert.True(t, s.SpawnUri)
}

func TestScan_InterpolationDoesNotSwallowLaterImports(t *testing.T) {
	// Modeling ${...} must not desync the file: a later import directive is still
	// captured after an interpolation with a same-quote inner string.
	src := `var s = "x ${g("y")} z";
import 'package:after/after.dart';`
	assert.Equal(t, []string{"after"}, pkgs(t, src))
}

func TestScan_SpawnUriInStringOrCommentDoesNotTrip(t *testing.T) {
	s := ScanSource([]byte(`
// call Isolate.spawnUri here later
final doc = "use spawnUri to load code";
void main() {}
`))
	assert.False(t, s.SpawnUri)
}

func TestScan_EmptyAndWhitespace(t *testing.T) {
	assert.Empty(t, ScanSource(nil).ImportPackages)
	assert.Empty(t, ScanSource([]byte("   \n\t  \n")).ImportPackages)
}
