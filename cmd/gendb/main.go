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

func fail(why string) {
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
	if err = json.Unmarshal(content, &current); err != nil {
		return false
	}
	return reflect.DeepEqual(current, new)
}

func main() {
	tomlDir := flag.String("reports", "reports", "Directory containing toml reports")
	jsonDir := flag.String("out", "out", "Directory to write JSON database to")
	flag.Parse()

	tomlFiles, err := ioutil.ReadDir(*tomlDir)
	if err != nil {
		fail(fmt.Sprintf("can't read %q: %s", *tomlDir, err))
	}

	jsonVulns := map[string][]osv.Entry{}
	for _, f := range tomlFiles {
		if !strings.HasSuffix(f.Name(), ".yaml") {
			continue
		}
		content, err := ioutil.ReadFile(filepath.Join(*tomlDir, f.Name()))
		if err != nil {
			fail(fmt.Sprintf("can't read %q: %s", f.Name(), err))
		}
		var vuln report.Report
		err = yaml.Unmarshal(content, &vuln)
		if err != nil {
			fail(fmt.Sprintf("unable to unmarshal %q: %s", f.Name(), err))
		}
		if err = vuln.Lint(); err != nil {
			fail(fmt.Sprintf("invalid vulnerability %q: %s", f.Name(), err))
		}

		name := strings.TrimSuffix(filepath.Base(f.Name()), filepath.Ext(f.Name()))

		// TODO(rolandshoemaker): once the HTML representation is ready this should be
		// the link to the HTML page.
		linkName := fmt.Sprintf("%s%s.yaml", dbURL, name)
		for _, e := range osv.Generate(name, linkName, vuln) {
			jsonVulns[e.Package.Name] = append(jsonVulns[e.Package.Name], e)
		}
	}

	index := make(osv.DBIndex, len(jsonVulns))
	for path, vulns := range jsonVulns {
		outPath := filepath.Join(*jsonDir, path)
		content, err := json.Marshal(vulns)
		if err != nil {
			fail(fmt.Sprintf("failed to marshal json: %s", err))
		}
		err = os.MkdirAll(filepath.Dir(outPath), 0700)
		if err != nil {
			fail(fmt.Sprintf("failed to create directory %q: %s", filepath.Dir(outPath), err))
		}
		err = ioutil.WriteFile(outPath+".json", content, 0644)
		if err != nil {
			fail(fmt.Sprintf("failed to write %q: %s", outPath+".json", err))
		}
		for _, v := range vulns {
			if v.Modified.After(index[path]) {
				index[path] = v.Modified
			}
		}
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
