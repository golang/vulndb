// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package client

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"reflect"
	"runtime"
	"testing"
	"time"

	"golang.org/x/vulndb/osv"
)

var testVuln string = `[
	{"ID":"ID","Package":{"Name":"golang.org/example/one","Ecosystem":"go"}, "Summary":"",
	 "Severity":2,"Affects":{"Ranges":[{"Type":"SEMVER","Introduced":"","Fixed":"v2.2.0"}]},
	 "ecosystem_specific":{"Symbols":["some_symbol_1"]
	}}]`

// index containing timestamps for package in testVuln.
var index string = `{
	"golang.org/example/one": "2020-03-09T10:00:00.81362141-07:00"
	}`

func serveTestVuln(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, testVuln)
}

func serveIndex(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, index)
}

// cachedTestVuln returns a function creating a local cache
// for db with `dbName` with a version of testVuln where
// Summary="cached" and LastModified happened after entry
// in the `index` for the same pkg.
func cachedTestVuln(dbName string) func() Cache {
	return func() Cache {
		c := &fsCache{}
		e := &osv.Entry{
			ID:       "ID1",
			Details:  "cached",
			Modified: time.Now(),
		}
		c.WriteEntries(dbName, "golang.org/example/one", []*osv.Entry{e})
		return c
	}
}

// createDirAndFile creates a directory `dir` if such directory does
// not exist and creates a `file` with `content` in the directory.
func createDirAndFile(dir, file, content string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return ioutil.WriteFile(path.Join(dir, file), []byte(content), 0644)
}

// localDB creates a local db with testVuln1, testVuln2, and index as contents.
func localDB(t *testing.T) (string, error) {
	dbName := t.TempDir()

	if err := createDirAndFile(path.Join(dbName, "/golang.org/example/"), "one.json", testVuln); err != nil {
		return "", err
	}
	if err := createDirAndFile(path.Join(dbName, ""), "index.json", index); err != nil {
		return "", err
	}
	return dbName, nil
}

func TestClient(t *testing.T) {
	if runtime.GOOS == "js" {
		t.Skip("skipping test: no network on js")
	}

	// Create a local http database.
	http.HandleFunc("/golang.org/example/one.json", serveTestVuln)
	http.HandleFunc("/index.json", serveIndex)

	l, err := net.Listen("tcp", "127.0.0.1:")
	if err != nil {
		t.Fatalf("failed to listen on 127.0.0.1: %s", err)
	}
	_, port, _ := net.SplitHostPort(l.Addr().String())
	go func() { http.Serve(l, nil) }()

	// Create a local file database.
	localDBName, err := localDB(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(localDBName)

	for _, test := range []struct {
		name        string
		source      string
		createCache func() Cache
		// cache summary for testVuln
		summary string
	}{
		// Test the http client without any cache.
		{name: "http-no-cache", source: "http://localhost:" + port, createCache: func() Cache { return nil }, summary: ""},
		// Test the http client with empty cache.
		{name: "http-empty-cache", source: "http://localhost:" + port, createCache: func() Cache { return &fsCache{} }, summary: ""},
		// Test the client with non-stale cache containing a version of testVuln2 where Summary="cached".
		{name: "http-cache", source: "http://localhost:" + port, createCache: cachedTestVuln("localhost"), summary: "cached"},
		// Repeat the same for local file client.
		{name: "file-no-cache", source: "file://" + localDBName, createCache: func() Cache { return nil }, summary: ""},
		{name: "file-empty-cache", source: "file://" + localDBName, createCache: func() Cache { return &fsCache{} }, summary: ""},
		// Cache does not play a role in local file databases.
		{name: "file-cache", source: "file://" + localDBName, createCache: cachedTestVuln(localDBName), summary: ""},
	} {
		// Create fresh cache location each time.
		cacheRoot = t.TempDir()

		client, err := NewClient([]string{test.source}, Options{HTTPCache: test.createCache()})
		if err != nil {
			t.Fatal(err)
		}

		vulns, err := client.Get("golang.org/example/one")
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
		if _, err := hs.Get(module); err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
	}
	expectedFetches := map[string]int{"/index.json": 3, "/a.json": 1, "/b.json": 1}
	if !reflect.DeepEqual(fetches, expectedFetches) {
		t.Errorf("unexpected fetches, got %v, want %v", fetches, expectedFetches)
	}
}
