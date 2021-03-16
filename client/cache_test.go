package client

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"golang.org/x/vulndb/osv"
)

func TestCache(t *testing.T) {
	originalRoot := cacheRoot
	defer func() { cacheRoot = originalRoot }()

	tmp, err := os.MkdirTemp("", "vulndb-cache")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmp)
	cacheRoot = tmp

	cache := &fsCache{}
	dbName := "vulndb.golang.org"

	_, _, err = cache.ReadIndex(dbName)
	if err != nil {
		t.Fatalf("ReadIndex failed for non-existent database: %v", err)
	}

	if err = os.Mkdir(filepath.Join(tmp, dbName), 0777); err != nil {
		t.Fatalf("os.Mkdir failed: %v", err)
	}
	_, _, err = cache.ReadIndex(dbName)
	if err != nil {
		t.Fatalf("ReadIndex failed for database without cached index: %v", err)
	}

	now := time.Now()
	expectedIdx := map[string]time.Time{
		"a.vuln.example.com": time.Time{}.Add(time.Hour),
		"b.vuln.example.com": time.Time{}.Add(time.Hour * 2),
		"c.vuln.example.com": time.Time{}.Add(time.Hour * 3),
	}
	if err = cache.WriteIndex(dbName, expectedIdx, now); err != nil {
		t.Fatalf("WriteIndex failed to write index: %v", err)
	}

	idx, retrieved, err := cache.ReadIndex(dbName)
	if err != nil {
		t.Fatalf("ReadIndex failed for database with cached index: %v", err)
	}
	if !reflect.DeepEqual(idx, expectedIdx) {
		t.Errorf("ReadIndex returned unexpected index, got:\n%s\nwant:\n%s", idx, expectedIdx)
	}
	if !retrieved.Equal(now) {
		t.Errorf("ReadIndex returned unexpected retrieved: got %s, want %s", retrieved, now)
	}

	if _, err = cache.ReadEntries(dbName, "vuln.example.com"); err != nil {
		t.Fatalf("ReadEntires failed for non-existent package: %v", err)
	}

	expectedEntries := []*osv.Entry{
		&osv.Entry{ID: "001"},
		&osv.Entry{ID: "002"},
		&osv.Entry{ID: "003"},
	}
	if err := cache.WriteEntries(dbName, "vuln.example.com", expectedEntries); err != nil {
		t.Fatalf("WriteEntries failed: %v", err)
	}

	entries, err := cache.ReadEntries(dbName, "vuln.example.com")
	if err != nil {
		t.Fatalf("ReadEntries failed for cached package: %v", err)
	}
	if !reflect.DeepEqual(entries, expectedEntries) {
		t.Errorf("ReadEntries returned unexpected entries, got:\n%v\nwant:\n%v", entries, expectedEntries)
	}
}
