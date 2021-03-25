package client

import (
	"encoding/json"
	"go/build"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/vulndb/osv"
)

// NOTE: this cache implementation should be internal to the go tooling
// (i.e. cmd/go/internal/something) so that the vulndb cache is owned
// by the go command. Also it is currently NOT CONCURRENCY SAFE since
// it does not implement file locking. When ported to the stdlib it
// should use cmd/go/internal/lockedfile.

// The cache uses a single JSON index file for each vulnerability database
// which contains the map from packages to the time the last
// vulnerability for that package was added/modified and the time that
// the index was retrieved from the vulnerability database. The JSON
// format is as follows:
//
// $GOPATH/pkg/mod/cache/download/vulndb/{db hostname}/indexes/index.json
//   {
//       Retrieved time.Time
//       Index osv.DBIndex
//   }
//
// Each package also has a JSON file which contains the array of vulnerability
// entries for the package. The JSON format is as follows:
//
// $GOPATH/pkg/mod/cache/download/vulndb/{db hostname}/{import path}/vulns.json
//   []*osv.Entry

type Cache interface {
	ReadIndex(string) (osv.DBIndex, time.Time, error)
	WriteIndex(string, osv.DBIndex, time.Time) error
	ReadEntries(string, string) ([]*osv.Entry, error)
	WriteEntries(string, string, []*osv.Entry) error
}

type fsCache struct{}

// NewFsCache returns a fresh filesystem cache.
// TODO: remove once the cache implementation reaches the go tooling repo.
func NewFsCache() Cache {
	return &fsCache{}
}

// should be cfg.GOMODCACHE when doing this inside the cmd/go/internal
var cacheRoot = filepath.Join(build.Default.GOPATH, "/pkg/mod/cache/download/vulndb")

type cachedIndex struct {
	Retrieved time.Time
	Index     osv.DBIndex
}

func (c *fsCache) ReadIndex(dbName string) (osv.DBIndex, time.Time, error) {
	b, err := os.ReadFile(filepath.Join(cacheRoot, dbName, "index.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, time.Time{}, nil
		}
		return nil, time.Time{}, err
	}
	var index cachedIndex
	if err := json.Unmarshal(b, &index); err != nil {
		return nil, time.Time{}, err
	}
	return index.Index, index.Retrieved, nil
}

func (c *fsCache) WriteIndex(dbName string, index osv.DBIndex, retrieved time.Time) error {
	path := filepath.Join(cacheRoot, dbName)
	if err := os.MkdirAll(path, 0777); err != nil {
		return err
	}
	j, err := json.Marshal(cachedIndex{
		Index:     index,
		Retrieved: retrieved,
	})
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(path, "index.json"), j, 0666); err != nil {
		return err
	}
	return nil
}

func (c *fsCache) ReadEntries(dbName string, p string) ([]*osv.Entry, error) {
	b, err := os.ReadFile(filepath.Join(cacheRoot, dbName, p, "vulns.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var entries []*osv.Entry
	if err := json.Unmarshal(b, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func (c *fsCache) WriteEntries(dbName string, p string, entries []*osv.Entry) error {
	path := filepath.Join(cacheRoot, dbName, p)
	if err := os.MkdirAll(path, 0777); err != nil {
		return err
	}
	j, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(path, "vulns.json"), j, 0666); err != nil {
		return err
	}
	return nil
}
