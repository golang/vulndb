package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"golang.org/x/vulndb/osv"
	"golang.org/x/vulndb/report"
)

type IndexEntry struct {
	LastModified   time.Time
	LastNewFinding time.Time
}

func fail(why string) {
	fmt.Fprintln(os.Stderr, why)
	os.Exit(1)
}

// TODO: obviously not for the real world
const dbURL = "https://team.git.corp.google.com/golang/vulndb/+/refs/heads/main/reports/"

func matchesCurrent(path string, new []osv.Entry) bool {
	var current []osv.Entry
	content, err := ioutil.ReadFile(path + ".json")
	if err != nil {
		fmt.Println("bad", err)
		return false
	}
	if err = json.Unmarshal(content, &current); err != nil {
		return false
	}
	return reflect.DeepEqual(current, new)
}

func main() {
	tomlDir := flag.String("reports", "Directory containing toml reports", "")
	jsonDir := flag.String("out", "Directory to write JSON database to", "")
	flag.Parse()

	tomlFiles, err := ioutil.ReadDir(*tomlDir)
	if err != nil {
		fail(fmt.Sprintf("can't read %q: %s", *tomlDir, err))
	}

	jsonVulns := map[string][]osv.Entry{}
	for _, f := range tomlFiles {
		if !strings.HasSuffix(f.Name(), ".toml") {
			continue
		}
		content, err := ioutil.ReadFile(filepath.Join(*tomlDir, f.Name()))
		if err != nil {
			fail(fmt.Sprintf("can't read %q: %s", f.Name(), err))
		}
		var vuln report.Report
		err = toml.Unmarshal(content, &vuln)
		if err != nil {
			fail(fmt.Sprintf("unable to unmarshal %q: %s", f.Name(), err))
		}
		if err = vuln.Lint(); err != nil {
			fail(fmt.Sprintf("invalid vulnerability %q: %s", f.Name(), err))
		}

		name := strings.TrimSuffix(filepath.Base(f.Name()), filepath.Ext(f.Name()))

		for _, e := range osv.Generate(name, fmt.Sprintf("%s%s.toml", dbURL, name), vuln) {
			jsonVulns[e.Package.Name] = append(jsonVulns[e.Package.Name], e)
		}
	}

	index := map[string]*IndexEntry{}
	if content, err := ioutil.ReadFile(filepath.Join(*jsonDir, "index.json")); err == nil {
		err = json.Unmarshal(content, &index)
		if err != nil {
			fail(fmt.Sprintf("failed to parse index: %s", err))
		}
	} else if err != nil && !os.IsNotExist(err) {
		fail(fmt.Sprintf("failed to read index %q: %s", filepath.Join(*jsonDir, "index.json"), err))
	}

	// TODO(bracewell): I'm pretty sure the freshness stuff is basically
	// completely broken at the moment.
	now := time.Now()
	for path, v := range jsonVulns {
		outPath := filepath.Join(*jsonDir, path)
		content, err := json.Marshal(v)
		if err != nil {
			fail(fmt.Sprintf("failed to marshal json: %s", err))
		}
		// fmt.Println("making", filepath.Dir(outPath))
		err = os.MkdirAll(filepath.Dir(outPath), 0700)
		if err != nil {
			fail(fmt.Sprintf("failed to create directory %q: %s", filepath.Dir(outPath), err))
		}
		// if there is already an index entry, only update the file
		// if the set of vulns differ from what is already on disk
		if _, ok := index[path]; ok && matchesCurrent(outPath, v) {
			// fmt.Println("skipping", outPath)
			continue
		}
		// fmt.Println("writing", outPath, string(content))
		err = ioutil.WriteFile(outPath+".json", content, 0644)
		if err != nil {
			fail(fmt.Sprintf("failed to write %q: %s", outPath+".json", err))
		}
		if index[path] == nil {
			index[path] = &IndexEntry{}
		}
		index[path].LastModified = now
		// also need to set the LastNewFinding, somewhat more complicated...
	}

	indexJSON, err := json.Marshal(index)
	if err != nil {
		fail(fmt.Sprintf("failed to marshal index json: %s", err))
	}
	err = ioutil.WriteFile(filepath.Join(*jsonDir, "index.json"), indexJSON, 0644)
	if err != nil {
		fail(fmt.Sprintf("failed to write index: %s", err))
	}
}
