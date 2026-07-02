// Package dartimports statically extracts the import/export/part directives and
// the dynamism markers from a single Dart source file.
//
// It is deliberately a pure, side-effect-free lexer: it NEVER evaluates the
// source and NEVER runs any Dart toolchain. Its only job is to answer, for the
// used-import reachability closure:
//
//   - which packages does this file import/export (the package segment of every
//     `package:NAME/...` URI, conditional-import alternates included), and
//   - does this file contain a dynamism construct (dart:mirrors reflection or
//     Isolate.spawnUri) that forbids a NOT_REACHABLE proof, and
//   - which relative `part 'x.dart';` files does it declare (so a caller can
//     detect an absent generated part — codegen not run — and refuse NR).
//
// Soundness bias: over-reporting an import or a dynamism marker only ever makes a
// package look MORE reachable (PACKAGE_REACHABLE / UNKNOWN), which is safe.
// The one thing that must never happen is UNDER-reporting a real import, so the
// directive scan handles the full lexical surface — line/block (nested) comments,
// single/double/triple/raw string literals, and escapes — to avoid mistaking a
// commented-out or stringized `import` for a real one, or missing a real import
// because an earlier string/comment was mis-tokenized.
package dartimports

import "strings"

// Scan is the result of lexing one Dart source file.
type Scan struct {
	// ImportPackages is the de-duplicated set of package names referenced by the
	// `package:NAME/...` URI of every import/export directive (both branches of a
	// conditional import are included). Relative and dart:/dart-ext: URIs are not
	// third-party packages and are omitted.
	ImportPackages []string

	// PartFiles is the list of relative URIs from `part 'x.dart';` directives
	// (never `part of ...`). A caller resolves these against the file's directory
	// to detect an absent generated part (e.g. a missing `*.g.dart`), which means
	// codegen has not run and the used-import set may be incomplete.
	PartFiles []string

	// MirrorsImport is true when the file imports `dart:mirrors`, re-enabling
	// runtime reflection (available on the Dart VM, forbidden in Flutter AOT).
	MirrorsImport bool

	// SpawnUri is true when the identifier `spawnUri` appears in code (outside
	// comments and string literals): Isolate.spawnUri loads code from a URI at
	// runtime, so a package could be pulled in without a static import.
	SpawnUri bool
}

// PackageName returns the package name from a `package:NAME/...` URI. The bool is
// false for any non-package URI (relative, dart:, dart-ext:, http:, …).
func PackageName(uri string) (string, bool) {
	const prefix = "package:"
	if !strings.HasPrefix(uri, prefix) {
		return "", false
	}
	rest := uri[len(prefix):]
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		rest = rest[:i]
	}
	if rest == "" {
		return "", false
	}
	return rest, true
}

// ScanSource lexes one Dart source file and returns its directive/dynamism facts.
func ScanSource(content []byte) Scan {
	s := &scanner{src: content, pkgSeen: map[string]struct{}{}}
	s.run()
	return s.out
}

type scanner struct {
	src     []byte
	i       int
	out     Scan
	pkgSeen map[string]struct{}
}

func (s *scanner) run() {
	for s.i < len(s.src) {
		c := s.src[s.i]
		switch {
		case c == '/' && s.peek(1) == '/':
			s.skipLineComment()
		case c == '/' && s.peek(1) == '*':
			s.skipBlockComment()
		case c == 'r' && (s.peek(1) == '\'' || s.peek(1) == '"'):
			s.i++ // consume the raw prefix; the string body has no escapes
			s.readString(true)
		case c == '\'' || c == '"':
			s.readString(false)
		case isIdentStart(c):
			word := s.readIdent()
			s.onIdent(word)
		default:
			s.i++
		}
	}
}

// onIdent reacts to a code-level identifier: it triggers directive collection for
// import/export/part keywords and flags the spawnUri dynamism marker.
func (s *scanner) onIdent(word string) {
	switch word {
	case "import", "export":
		s.collectDirective(false)
	case "part":
		s.collectDirective(true)
	case "spawnUri":
		s.out.SpawnUri = true
	}
}

// collectDirective is entered just after an import/export/part keyword. It first
// confirms the keyword is actually a directive (the next meaningful token is a
// string-literal URI); if not — e.g. `part of ...`, or `export` used as an
// identifier — it returns without consuming the following tokens as URIs. When it
// is a directive, it collects every string-literal URI up to the terminating `;`
// (capturing both branches of a conditional import).
func (s *scanner) collectDirective(isPart bool) {
	s.skipWsAndComments()
	if !s.atStringStart() {
		return // not a directive (e.g. `part of`, or a non-directive identifier)
	}
	// A directive URI is a stringLiteral, which may be several adjacent string
	// literals concatenated (whitespace/comments between them do not break the
	// concatenation). A conditional import's alternate URIs, by contrast, are
	// separated by an `if (...)` clause — i.e. by non-string tokens. So: append
	// adjacent strings into one pending URI, and flush (start a new URI) whenever
	// a non-string, non-whitespace token appears. This both reconstructs a split
	// URI (never under-counting a real package → no false NOT_REACHABLE) and keeps
	// conditional-import branches as distinct used tokens.
	var pending strings.Builder
	building := false
	flush := func() {
		if building {
			s.recordURI(pending.String(), isPart)
			pending.Reset()
			building = false
		}
	}
	for s.i < len(s.src) {
		c := s.src[s.i]
		switch {
		case c == ';':
			s.i++
			flush()
			return
		case c == '/' && s.peek(1) == '/':
			s.skipLineComment()
		case c == '/' && s.peek(1) == '*':
			s.skipBlockComment()
		case c == 'r' && (s.peek(1) == '\'' || s.peek(1) == '"'):
			s.i++
			pending.WriteString(s.readString(true))
			building = true
		case c == '\'' || c == '"':
			pending.WriteString(s.readString(false))
			building = true
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			s.i++ // whitespace does not break adjacent-string concatenation
		default:
			flush() // a non-string token (if/show/hide/as/…) ends the current URI
			s.i++
		}
	}
	flush()
}

// recordURI classifies one directive URI.
func (s *scanner) recordURI(uri string, isPart bool) {
	if isPart {
		// A part URI is a relative same-library file; record it for the absent
		// generated-part check. Scheme URIs (package:/dart:) are not valid parts.
		if !strings.Contains(uri, ":") {
			s.out.PartFiles = append(s.out.PartFiles, uri)
		}
		return
	}
	if uri == "dart:mirrors" {
		s.out.MirrorsImport = true
	}
	if name, ok := PackageName(uri); ok {
		if _, dup := s.pkgSeen[name]; !dup {
			s.pkgSeen[name] = struct{}{}
			s.out.ImportPackages = append(s.out.ImportPackages, name)
		}
	}
}

// readString consumes a string literal starting at the opening quote and returns
// its content. When raw is true no backslash escaping is applied. Triple-quoted
// strings are supported. On unterminated input it consumes to EOF and returns
// what it read (a lenient degrade — a truncated file must not desync the lexer).
func (s *scanner) readString(raw bool) string {
	q := s.src[s.i]
	triple := s.peek(1) == q && s.peek(2) == q
	if triple {
		s.i += 3
	} else {
		s.i++
	}

	var b strings.Builder
	for s.i < len(s.src) {
		c := s.src[s.i]
		if !raw && c == '\\' {
			if s.i+1 < len(s.src) {
				b.WriteByte(s.src[s.i+1])
				s.i += 2
			} else {
				s.i++
			}
			continue
		}
		if triple {
			if c == q && s.peek(1) == q && s.peek(2) == q {
				s.i += 3
				return b.String()
			}
		} else {
			if c == q {
				s.i++
				return b.String()
			}
			if c == '\n' {
				// A non-triple string cannot span a raw newline; stop here rather
				// than run away over the rest of the file.
				return b.String()
			}
		}
		b.WriteByte(c)
		s.i++
	}
	return b.String()
}

func (s *scanner) readIdent() string {
	start := s.i
	for s.i < len(s.src) && isIdentPart(s.src[s.i]) {
		s.i++
	}
	return string(s.src[start:s.i])
}

func (s *scanner) skipLineComment() {
	s.i += 2
	for s.i < len(s.src) && s.src[s.i] != '\n' {
		s.i++
	}
}

// skipBlockComment consumes a /* ... */ comment, honoring Dart's nesting.
func (s *scanner) skipBlockComment() {
	s.i += 2
	depth := 1
	for s.i < len(s.src) && depth > 0 {
		if s.src[s.i] == '/' && s.peek(1) == '*' {
			depth++
			s.i += 2
			continue
		}
		if s.src[s.i] == '*' && s.peek(1) == '/' {
			depth--
			s.i += 2
			continue
		}
		s.i++
	}
}

func (s *scanner) skipWsAndComments() {
	for s.i < len(s.src) {
		c := s.src[s.i]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			s.i++
		case c == '/' && s.peek(1) == '/':
			s.skipLineComment()
		case c == '/' && s.peek(1) == '*':
			s.skipBlockComment()
		default:
			return
		}
	}
}

// atStringStart reports whether the cursor is at the start of a string literal
// (including a raw-prefixed one).
func (s *scanner) atStringStart() bool {
	if s.i >= len(s.src) {
		return false
	}
	c := s.src[s.i]
	if c == '\'' || c == '"' {
		return true
	}
	return c == 'r' && (s.peek(1) == '\'' || s.peek(1) == '"')
}

func (s *scanner) peek(n int) byte {
	if s.i+n < len(s.src) {
		return s.src[s.i+n]
	}
	return 0
}

func isIdentStart(c byte) bool {
	return c == '_' || c == '$' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentPart(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9')
}
