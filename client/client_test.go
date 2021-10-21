// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package client

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vulndb/internal"
	"golang.org/x/vulndb/osv"
)

var (
	testVuln = `
	{"ID":"ID","Package":{"Name":"golang.org/example/one","Ecosystem":"go"}, "Summary":"",
	 "Severity":2,"Affects":{"Ranges":[{"Type":"SEMVER","Introduced":"","Fixed":"v2.2.0"}]},
	 "ecosystem_specific":{"Symbols":["some_symbol_1"]
	}}`

	testVulns = "[" + testVuln + "]"
)

var (
	// index containing timestamps for package in testVuln.
	index string = `{
	"golang.org/example/one": "2020-03-09T10:00:00.81362141-07:00"
	}`
	// index of IDs
	idIndex string = `["ID"]`
)

// testCache for testing purposes
type testCache struct {
	indexMap   map[string]osv.DBIndex
	indexStamp map[string]time.Time
	vulnMap    map[string]map[string][]*osv.Entry
}

func freshTestCache() *testCache {
	return &testCache{
		indexMap:   make(map[string]osv.DBIndex),
		indexStamp: make(map[string]time.Time),
		vulnMap:    make(map[string]map[string][]*osv.Entry),
	}
}

func (tc *testCache) ReadIndex(db string) (osv.DBIndex, time.Time, error) {
	index, ok := tc.indexMap[db]
	if !ok {
		return nil, time.Time{}, nil
	}
	stamp, ok := tc.indexStamp[db]
	if !ok {
		return nil, time.Time{}, nil
	}
	return index, stamp, nil
}

func (tc *testCache) WriteIndex(db string, index osv.DBIndex, stamp time.Time) error {
	tc.indexMap[db] = index
	tc.indexStamp[db] = stamp
	return nil
}

func (tc *testCache) ReadEntries(db, module string) ([]*osv.Entry, error) {
	mMap, ok := tc.vulnMap[db]
	if !ok {
		return nil, nil
	}
	return mMap[module], nil
}

func (tc *testCache) WriteEntries(db, module string, entries []*osv.Entry) error {
	mMap, ok := tc.vulnMap[db]
	if !ok {
		mMap = make(map[string][]*osv.Entry)
		tc.vulnMap[db] = mMap
	}
	mMap[module] = append(mMap[module], entries...)
	return nil
}

// cachedTestVuln returns a function creating a local cache
// for db with `dbName` with a version of testVuln where
// Summary="cached" and LastModified happened after entry
// in the `index` for the same pkg.
func cachedTestVuln(dbName string) Cache {
	c := freshTestCache()
	e := &osv.Entry{
		ID:       "ID1",
		Details:  "cached",
		Modified: time.Now(),
	}
	c.WriteEntries(dbName, "golang.org/example/one", []*osv.Entry{e})
	return c
}

// createDirAndFile creates a directory `dir` if such directory does
// not exist and creates a `file` with `content` in the directory.
func createDirAndFile(dir, file, content string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return ioutil.WriteFile(path.Join(dir, file), []byte(content), 0644)
}

// localDB creates a local db with testVulns and index as contents.
func localDB(t *testing.T) (string, error) {
	dbName := t.TempDir()
	for _, f := range []struct {
		dir, filename, content string
	}{
		{"golang.org/example", "one.json", testVulns},
		{"", "index.json", index},
		{internal.IDDirectory, "ID.json", testVuln},
		{internal.IDDirectory, "index.json", idIndex},
	} {
		if err := createDirAndFile(path.Join(dbName, f.dir), f.filename, f.content); err != nil {
			return "", err
		}
	}
	return dbName, nil
}

func newTestServer() *httptest.Server {
	dataHandler := func(data string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			io.WriteString(w, data)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/golang.org/example/one.json", dataHandler(testVulns))
	mux.HandleFunc("/index.json", dataHandler(index))
	mux.HandleFunc(fmt.Sprintf("/%s/ID.json", internal.IDDirectory), dataHandler(testVuln))
	mux.HandleFunc("/ID/index.json", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, idIndex)
	})
	return httptest.NewServer(mux)
}

func TestClient(t *testing.T) {
	if runtime.GOOS == "js" {
		t.Skip("skipping test: no network on js")
	}

	// Create a local http database.
	srv := newTestServer()
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	dbName := u.Hostname()

	// Create a local file database.
	localDBName, err := localDB(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(localDBName)

	for _, test := range []struct {
		name   string
		source string
		cache  Cache
		// cache summary for testVuln
		summary string
	}{
		// Test the http client without any cache.
		{name: "http-no-cache", source: srv.URL, cache: nil, summary: ""},
		// Test the http client with empty cache.
		{name: "http-empty-cache", source: srv.URL, cache: freshTestCache(), summary: ""},
		// Test the client with non-stale cache containing a version of testVuln2 where Summary="cached".
		{name: "http-cache", source: srv.URL, cache: cachedTestVuln(dbName), summary: "cached"},
		// Repeat the same for local file client.
		{name: "file-no-cache", source: "file://" + localDBName, cache: nil, summary: ""},
		{name: "file-empty-cache", source: "file://" + localDBName, cache: freshTestCache(), summary: ""},
		// Cache does not play a role in local file databases.
		{name: "file-cache", source: "file://" + localDBName, cache: cachedTestVuln(localDBName), summary: ""},
	} {
		client, err := NewClient([]string{test.source}, Options{HTTPCache: test.cache})
		if err != nil {
			t.Fatal(err)
		}

		vulns, err := client.GetByModule("golang.org/example/one")
		if err != nil {
			t.Fatal(err)
		}

		if len(vulns) != 1 {
			t.Errorf("%s: want 1 vuln for golang.org/example/one; got %v", test.name, len(vulns))
		}

		if v := vulns[0]; v.Details != test.summary {
			t.Errorf("%s: want '%s' summary for testVuln; got '%s'", test.name, test.summary, v.Details)
		}
	}
}

func TestCorrectFetchesNoCache(t *testing.T) {
	fetches := map[string]int{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches[r.URL.Path]++
		if r.URL.Path == "/index.json" {
			j, _ := json.Marshal(osv.DBIndex{
				"a": time.Now(),
				"b": time.Now(),
			})
			w.Write(j)
		} else {
			w.Write([]byte("[]"))
		}
	}))
	defer ts.Close()

	hs := &httpSource{url: ts.URL, c: new(http.Client)}
	for _, module := range []string{"a", "b", "c"} {
		if _, err := hs.GetByModule(module); err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
	}
	expectedFetches := map[string]int{"/index.json": 3, "/a.json": 1, "/b.json": 1}
	if !reflect.DeepEqual(fetches, expectedFetches) {
		t.Errorf("unexpected fetches, got %v, want %v", fetches, expectedFetches)
	}
}

// Make sure that a cached index is used in the case it is stale
// but there were no changes to it at the server side.
func TestCorrectFetchesNoChangeIndex(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/index.json" {
			w.WriteHeader(http.StatusNotModified)
		}
	}))
	defer ts.Close()
	url, _ := url.Parse(ts.URL)

	// set timestamp so that cached index is stale,
	// i.e., more than two hours old.
	timeStamp := time.Now().Add(time.Hour * (-3))
	index := osv.DBIndex{"a": timeStamp}
	cache := freshTestCache()
	cache.WriteIndex(url.Hostname(), index, timeStamp)

	e := &osv.Entry{
		ID:       "ID1",
		Modified: timeStamp,
	}
	cache.WriteEntries(url.Hostname(), "a", []*osv.Entry{e})

	client, err := NewClient([]string{ts.URL}, Options{HTTPCache: cache})
	if err != nil {
		t.Fatal(err)
	}
	vulns, err := client.GetByModule("a")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(vulns, []*osv.Entry{e}) {
		t.Errorf("want %v vuln; got %v", e, vulns)
	}
}

func TestClientByID(t *testing.T) {
	if runtime.GOOS == "js" {
		t.Skip("skipping test: no network on js")
	}

	srv := newTestServer()
	defer srv.Close()

	// Create a local file database.
	localDBName, err := localDB(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(localDBName)

	var want osv.Entry
	if err := json.Unmarshal([]byte(testVuln), &want); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		source string
	}{
		{name: "http", source: srv.URL},
		{name: "file", source: "file://" + localDBName},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, err := NewClient([]string{test.source}, Options{})
			if err != nil {
				t.Fatal(err)
			}
			got, err := client.GetByID("ID")
			if err != nil {
				t.Fatal(err)
			}
			if !cmp.Equal(got, &want) {
				t.Errorf("got\n%+v\nwant\n%+v", got, &want)
			}
		})
	}
}

func TestListIDs(t *testing.T) {
	if runtime.GOOS == "js" {
		t.Skip("skipping test: no network on js")
	}

	srv := newTestServer()
	defer srv.Close()

	// Create a local file database.
	localDBName, err := localDB(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(localDBName)

	want := []string{"ID"}
	for _, test := range []struct {
		name   string
		source string
	}{
		{name: "http", source: srv.URL},
		{name: "file", source: "file://" + localDBName},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, err := NewClient([]string{test.source}, Options{})
			if err != nil {
				t.Fatal(err)
			}
			got, err := client.ListIDs()
			if err != nil {
				t.Fatal(err)
			}
			if !cmp.Equal(got, want) {
				t.Errorf("got\n%+v\nwant\n%+v", got, want)
			}
		})
	}
}
