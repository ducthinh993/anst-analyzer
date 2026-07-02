package lockfilekit

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFetch_OfflineMissReturnsSentinel(t *testing.T) {
	f := &Fetcher{Ecosystem: "test", Offline: true, CacheDir: t.TempDir()}
	_, err := f.Fetch(context.Background(), "http://unused.invalid/artifact", "pkg@1.0.0")
	assert.ErrorIs(t, err, ErrOfflineMiss,
		"an offline cache miss must return ErrOfflineMiss (caller → MappingUnknown → UNKNOWN), never a false clean")
}

func TestFetch_DownloadsAndCaches(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		_, _ = w.Write([]byte("artifact-bytes"))
	}))
	defer srv.Close()

	cache := t.TempDir()
	f := &Fetcher{Ecosystem: "test", CacheDir: cache}

	data, err := f.Fetch(context.Background(), srv.URL, "pkg@1.0.0")
	require.NoError(t, err)
	assert.Equal(t, "artifact-bytes", string(data))
	assert.Equal(t, 1, hits)

	// Second fetch is served from cache (no new server hit), even offline.
	offline := &Fetcher{Ecosystem: "test", CacheDir: cache, Offline: true}
	data2, err := offline.Fetch(context.Background(), srv.URL, "pkg@1.0.0")
	require.NoError(t, err)
	assert.Equal(t, "artifact-bytes", string(data2))
	assert.Equal(t, 1, hits, "a cached artifact must not re-hit the network")
}

func TestFetch_Non200IsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	f := &Fetcher{Ecosystem: "test", CacheDir: t.TempDir()}
	_, err := f.Fetch(context.Background(), srv.URL, "pkg@1.0.0")
	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrOfflineMiss), "a 404 is a fetch error, not an offline miss")
}

func TestFetch_CachePathIsDeterministicPerKey(t *testing.T) {
	f := &Fetcher{Ecosystem: "test", CacheDir: t.TempDir()}
	dir := t.TempDir()
	assert.Equal(t, f.cachePath(dir, "a@1"), f.cachePath(dir, "a@1"), "same key → same path")
	assert.NotEqual(t, f.cachePath(dir, "a@1"), f.cachePath(dir, "a@2"), "different key → different path")
}
