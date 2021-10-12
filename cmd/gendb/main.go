// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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

	"golang.org/x/vulndb/osv"
	"golang.org/x/vulndb/report"
	"gopkg.in/yaml.v2"
)

func failf(format string, args ...interface{}) {
	why := fmt.Sprintf(format, args...)
	fmt.Fprintln(os.Stderr, why)
	os.Exit(1)
}

// TODO(rolandshoemaker): once we have the HTML representation ready this should
// be the prefix for that.
const dbURL = "https://go.googlesource.com/vulndb/+/refs/heads/master/reports/"

func matchesCurrent(path string, new []osv.Entry) bool {
	var current []osv.Entry
	content, err := ioutil.ReadFile(path + ".json")
	if err != nil {
		return false
	}
	if err := json.Unmarshal(content, &current); err != nil {
		return false
	}
	return reflect.DeepEqual(current, new)
}

func main() {
	yamlDir := flag.String("reports", "reports", "Directory containing yaml reports")
	jsonDir := flag.String("out", "out", "Directory to write JSON database to")
	flag.Parse()

	yamlFiles, err := ioutil.ReadDir(*yamlDir)
	if err != nil {
		failf("can't read %q: %s", *yamlDir, err)
	}

	jsonVulns := map[string][]osv.Entry{}
	var entries []osv.Entry
	for _, f := range yamlFiles {
		if !strings.HasSuffix(f.Name(), ".yaml") {
			continue
		}
		content, err := ioutil.ReadFile(filepath.Join(*yamlDir, f.Name()))
		if err != nil {
			failf("can't read %q: %s", f.Name(), err)
		}
		var vuln report.Report
		if err := yaml.UnmarshalStrict(content, &vuln); err != nil {
			failf("unable to unmarshal %q: %s", f.Name(), err)
		}
		if lints := vuln.Lint(); len(lints) > 0 {
			fmt.Fprintf(os.Stderr, "invalid vulnerability file %q:\n", os.Args[1])
			for _, lint := range lints {
				fmt.Fprintf(os.Stderr, "\t%s\n", lint)
			}
			os.Exit(1)
		}

		name := strings.TrimSuffix(filepath.Base(f.Name()), filepath.Ext(f.Name()))

		// TODO(rolandshoemaker): once the HTML representation is ready this should be
		// the link to the HTML page.
		linkName := fmt.Sprintf("%s%s.yaml", dbURL, name)
		entry, paths := osv.Generate(name, linkName, vuln)
		for _, path := range paths {
			jsonVulns[path] = append(jsonVulns[path], entry)
		}
		entries = append(entries, entry)
	}

	index := make(osv.DBIndex, len(jsonVulns))
	for path, vulns := range jsonVulns {
		outPath := filepath.Join(*jsonDir, path)
		content, err := json.Marshal(vulns)
		if err != nil {
			failf("failed to marshal json: %s", err)
		}
		if err := os.MkdirAll(filepath.Dir(outPath), 0700); err != nil {
			failf("failed to create directory %q: %s", filepath.Dir(outPath), err)
		}
		if err := ioutil.WriteFile(outPath+".json", content, 0644); err != nil {
			failf("failed to write %q: %s", outPath+".json", err)
		}
		for _, v := range vulns {
			if v.Modified.After(index[path]) || v.Published.After(index[path]) {
				index[path] = v.Modified
			}
		}
	}

	indexJSON, err := json.Marshal(index)
	if err != nil {
		failf("failed to marshal index json: %s", err)
	}
	if err := ioutil.WriteFile(filepath.Join(*jsonDir, "index.json"), indexJSON, 0644); err != nil {
		failf("failed to write index: %s", err)
	}

	// Write a directory containing entries by ID.
	idDir := filepath.Join(*jsonDir, "byID")
	if err := os.MkdirAll(idDir, 0700); err != nil {
		failf("failed to create directory %q: %v", idDir, err)
	}
	for _, e := range entries {
		outPath := filepath.Join(idDir, e.ID+".json")
		content, err := json.Marshal(e)
		if err != nil {
			failf("failed to marshal json: %v", err)
		}
		if err := ioutil.WriteFile(outPath, content, 0644); err != nil {
			failf("failed to write %q: %v", outPath, err)
		}
	}
}
