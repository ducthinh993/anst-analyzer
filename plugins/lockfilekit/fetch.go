package lockfilekit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// ErrOfflineMiss is returned by Fetcher.Fetch when Offline is set and the
// requested artifact is not already cached. The caller MUST treat this as
// MappingUnknown (→ UNKNOWN), never as "package absent" — an unfetched artifact
// tells us nothing about reachability ("unknown ≠ safe").
var ErrOfflineMiss = errors.New("lockfilekit: artifact not cached and fetch is offline")

// maxArtifactBytes caps a downloaded artifact to bound memory and disk. A larger
// artifact is refused (the caller degrades to MappingUnknown) rather than read.
const maxArtifactBytes = 256 << 20 // 256 MiB

// Fetcher retrieves package artifacts by resolved coordinate over HTTP and
// caches them on disk. It NEVER executes anything: it is a read-only download +
// cache, the ACE-safe substitute for running a package manager. A plugin indexes
// the returned bytes (JAR zip entries, tarball paths, etc.) in pure Go.
type Fetcher struct {
	// Ecosystem is the cache namespace (e.g. "maven", "hex"); artifacts live
	// under <CacheDir>/<Ecosystem>/.
	Ecosystem string

	// HTTPClient is used for downloads. When nil a default client with a 60s
	// timeout is used.
	HTTPClient *http.Client

	// Offline, when true, restricts Fetch to the on-disk cache: a miss returns
	// ErrOfflineMiss instead of hitting the network.
	Offline bool

	// CacheDir overrides the cache root. When empty it defaults to
	// os.UserCacheDir()/commit0-analyzer/reach.
	CacheDir string
}

// cacheRoot resolves the ecosystem cache directory, creating it on demand.
func (f *Fetcher) cacheRoot() (string, error) {
	base := f.CacheDir
	if base == "" {
		userCache, err := os.UserCacheDir()
		if err != nil {
			return "", fmt.Errorf("lockfilekit: locate user cache dir: %w", err)
		}
		base = filepath.Join(userCache, "commit0-analyzer", "reach")
	}
	dir := filepath.Join(base, f.Ecosystem)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("lockfilekit: create cache dir %s: %w", dir, err)
	}
	return dir, nil
}

// cachePath returns the on-disk path for a cache key. The key (typically a
// "name@version" coordinate) is hashed so arbitrary coordinates map to safe
// filenames with no path-traversal risk.
func (f *Fetcher) cachePath(dir, key string) string {
	sum := sha256.Sum256([]byte(key))
	return filepath.Join(dir, hex.EncodeToString(sum[:])+".artifact")
}

// Fetch returns the artifact bytes for cacheKey, serving from the on-disk cache
// when present and otherwise downloading from url (unless Offline). A successful
// download is written to the cache atomically before it is returned.
//
// Fetch performs a plain HTTP GET and copies the body to disk. It does not
// interpret, unpack, or execute the artifact — indexing is the caller's pure-Go
// concern.
func (f *Fetcher) Fetch(ctx context.Context, url, cacheKey string) ([]byte, error) {
	dir, err := f.cacheRoot()
	if err != nil {
		return nil, err
	}
	path := f.cachePath(dir, cacheKey)

	if data, readErr := os.ReadFile(path); readErr == nil {
		return data, nil
	}

	if f.Offline {
		return nil, ErrOfflineMiss
	}

	client := f.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("lockfilekit: build request for %s: %w", url, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("lockfilekit: fetch %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("lockfilekit: fetch %s: unexpected status %d", url, resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxArtifactBytes+1))
	if err != nil {
		return nil, fmt.Errorf("lockfilekit: read %s: %w", url, err)
	}
	if int64(len(data)) > maxArtifactBytes {
		return nil, fmt.Errorf("lockfilekit: artifact %s exceeds %d bytes", url, maxArtifactBytes)
	}

	if writeErr := writeCacheFile(path, data); writeErr != nil {
		// A cache-write failure is not fatal: return the bytes we fetched.
		return data, nil //nolint:nilerr // best-effort cache; data is valid
	}
	return data, nil
}

// writeCacheFile writes data to path atomically (write temp + rename) so a
// concurrent reader never observes a half-written artifact.
func writeCacheFile(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".artifact-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}
