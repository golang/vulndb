package client

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"testing"
	"time"

	"golang.org/x/vulndb/osv"
)

var testVuln1 string = `[
	{"ID":"ID1","Package":{"Name":"golang.org/example/one","Ecosystem":"go"}, "Summary":"",
	 "Severity":2,"Affects":{"Ranges":[{"Type":2,"Introduced":"","Fixed":"v2.2.0"}]},
	 "ecosystem_specific":{"Symbols":["some_symbol_1"]
	}}]`

var testVuln2 string = `[
	{"ID":"ID2","Package":{"Name":"golang.org/example/two","Ecosystem":"go"}, "Summary":"",
	 "Severity":2,"Affects":{"Ranges":[{"Type":2,"Introduced":"","Fixed":"v2.1.0"}]},
	 "ecosystem_specific":{"Symbols":["some_symbol_2"]
	}}]`

// index containing timestamps for packages in testVuln1 and testVuln2.
var index string = `{
	"golang.org/example/one": "2020-03-09T10:00:00.81362141-07:00",
	"golang.org/example/two": "2019-02-05T09:00:00.31561157-07:00"
	}`

func serveTestVuln1(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, testVuln1)
}

func serveTestVuln2(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, testVuln2)
}

func serveIndex(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, index)
}

// cachedTestVuln2 returns a function creating a local cache
// for db with `dbName` with a version of testVuln2 where
// Summary="cached" and LastModified happened after entry
// in the `index` for the same pkg.
func cachedTestVuln2(dbName string) func() Cache {
	return func() Cache {
		c := &fsCache{}
		e := &osv.Entry{
			ID:           "ID2",
			Summary:      "cached",
			LastModified: time.Now(),
		}
		c.WriteEntries(dbName, "golang.org/example/two", []*osv.Entry{e})
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

	if err := createDirAndFile(path.Join(dbName, "/golang.org/example/"), "one.json", testVuln1); err != nil {
		return "", err
	}
	if err := createDirAndFile(path.Join(dbName, "/golang.org/example/"), "two.json", testVuln2); err != nil {
		return "", err
	}
	if err := createDirAndFile(path.Join(dbName, ""), "index.json", index); err != nil {
		return "", err
	}
	return dbName, nil
}

func TestClient(t *testing.T) {
	// Create a local http database.
	http.HandleFunc("/golang.org/example/one.json", serveTestVuln1)
	http.HandleFunc("/golang.org/example/two.json", serveTestVuln2)
	http.HandleFunc("/index.json", serveIndex)
	go func() { http.ListenAndServe(":8080", nil) }()

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
		noVulns     int
		summaries   map[string]string
	}{
		// Test the http client without any cache.
		{name: "http-no-cache", source: "http://localhost:8080", createCache: func() Cache { return nil }, noVulns: 2, summaries: map[string]string{"ID1": "", "ID2": ""}},
		// Test the http client with empty cache.
		{name: "http-empty-cache", source: "http://localhost:8080", createCache: func() Cache { return &fsCache{} }, noVulns: 2, summaries: map[string]string{"ID1": "", "ID2": ""}},
		// Test the client with non-stale cache containing a version of testVuln2 where Summary="cached".
		{name: "http-cache", source: "http://localhost:8080", createCache: cachedTestVuln2("localhost"), noVulns: 2, summaries: map[string]string{"ID1": "", "ID2": "cached"}},
		// Repeat the same for local file client.
		{name: "file-no-cache", source: "file://" + localDBName, createCache: func() Cache { return nil }, noVulns: 2, summaries: map[string]string{"ID1": "", "ID2": ""}},
		{name: "file-empty-cache", source: "file://" + localDBName, createCache: func() Cache { return &fsCache{} }, noVulns: 2, summaries: map[string]string{"ID1": "", "ID2": ""}},
		// Cache does not play a role in local file databases.
		{name: "file-cache", source: "file://" + localDBName, createCache: cachedTestVuln2(localDBName), noVulns: 2, summaries: map[string]string{"ID1": "", "ID2": ""}},
	} {
		// Create fresh cache location each time.
		cacheRoot = t.TempDir()

		client, err := NewClient([]string{test.source}, Options{HTTPCache: test.createCache()})
		if err != nil {
			t.Fatal(err)
		}

		vulns, err := client.Get([]string{"golang.org/example/one", "golang.org/example/two"})
		if err != nil {
			t.Fatal(err)
		}
		if len(vulns) != test.noVulns {
			t.Errorf("want %v vulns for %s; got %v", test.noVulns, test.name, len(vulns))
		}

		for _, v := range vulns {
			if s, ok := test.summaries[v.ID]; !ok || v.Summary != s {
				t.Errorf("want '%s' summary for vuln with id %v in %s; got '%s'", s, v.ID, test.name, v.Summary)
			}
		}
	}
}
