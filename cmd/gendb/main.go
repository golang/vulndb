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

	"github.com/BurntSushi/toml"
	"golang.org/x/vulndb/osv"
	"golang.org/x/vulndb/report"
)

func fail(why string) {
	fmt.Fprintln(os.Stderr, why)
	os.Exit(1)
}

// TODO: obviously not for the real world
const dbURL = "https://go.googlesource.com/vulndb/+/refs/heads/main/reports/"

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
			if v.LastModified.After(index[path]) {
				index[path] = v.LastModified
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
