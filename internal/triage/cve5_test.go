// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package triage

import (
	"context"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/exp/maps"
	"golang.org/x/tools/txtar"
	"golang.org/x/vulndb/internal"
	"golang.org/x/vulndb/internal/cve5"
	"golang.org/x/vulndb/internal/cvelistrepo"
	"golang.org/x/vulndb/internal/gitrepo"
	"golang.org/x/vulndb/internal/pkgsite"
	"golang.org/x/vulndb/internal/report"
	"gopkg.in/yaml.v3"
)

var (
	updateTxtarRepo = flag.Bool("update-repo", false, "update the .txtar file with real CVE data (this takes a while)")
	update          = flag.Bool("update", false, "update the golden files")
	newCVEs         = flag.Bool("new-cves", false, "pick new random CVEs and update the .txtar file")
	testCVEs        map[string]bool
)

func TestMain(m *testing.M) {
	if err := setup(context.Background()); err != nil {
		log.Fatal(err)
	}
	os.Exit(m.Run())
}

func setup(ctx context.Context) error {
	flag.Parse()
	goFile, notGoFile := filepath.Join("testdata", "cve", "go_cves.txt"), filepath.Join("testdata", "cve", "not_go_cves.txt")
	if *newCVEs {
		const n = 25
		goCVEs, notGoCVEs, err := pickRandomCVEs(ctx, n)
		if err != nil {
			return err
		}
		if err := writeLines(goCVEs, goFile); err != nil {
			return err
		}
		if err := writeLines(notGoCVEs, notGoFile); err != nil {
			return err
		}
	}
	goCVEs, err := internal.ReadFileLines(goFile)
	if err != nil {
		return err
	}
	notGoCVEs, err := internal.ReadFileLines(notGoFile)
	if err != nil {
		return err
	}
	testCVEs = make(map[string]bool)
	for _, c := range goCVEs {
		testCVEs[c] = true
	}
	for _, c := range notGoCVEs {
		testCVEs[c] = false
	}
	if *updateTxtarRepo || *newCVEs {
		return cvelistrepo.UpdateTxtar(ctx, cvelistrepo.URLv5, maps.Keys(testCVEs))
	}
	return nil
}

func TestAffectsGo(t *testing.T) {
	if *usePkgsite {
		os.RemoveAll(filepath.Join("testdata", "pkgsite", t.Name()))
	}
	wantFunc := func(t *testing.T, cve *cve5.CVERecord) ([]txtar.File, error) {
		pc, err := pkgsite.TestClient(t, *usePkgsite)
		if err != nil {
			return nil, err
		}
		ctx := context.Background()
		tr := &CVE5Triager{pc: pc}
		r, err := tr.AffectsGo(ctx, cve)
		if err != nil {
			return nil, err
		}
		agb, err := yaml.Marshal(r)
		if err != nil {
			return nil, err
		}
		// Instead of erroring if we have a mismatch, merely store the result.
		// The CVE triage algorithm will likely never be perfect because some
		// CVEs simply don't have enough information to determine if they affect
		// Go.
		type eval struct {
			InVulndb bool `yaml:"in_vulndb"`
			Mismatch bool `yaml:"mismatch,omitempty"`
		}
		inVulndb, ok := testCVEs[cve.SourceID()]
		if !ok {
			return nil, fmt.Errorf("%s is not in list of test CVEs", cve.SourceID())
		}
		e := &eval{
			InVulndb: inVulndb,
			Mismatch: (inVulndb && r == nil) || (!inVulndb && r != nil),
		}
		eb, err := yaml.Marshal(e)
		if err != nil {
			return nil, err
		}
		return []txtar.File{
			{Name: "affects_go_result", Data: agb},
			{Name: "eval", Data: eb}}, nil
	}

	if err := cvelistrepo.RunTest(t, *update, wantFunc); err != nil {
		t.Fatal(err)
	}
}

// pickRandomCVEs chooses n*3 random CVEs that affect Go and n random CVEs
// that do not affect Go.
// We take a bigger sample of Go CVEs because we care more about false
// negatives than false positives.
func pickRandomCVEs(ctx context.Context, n int) ([]string, []string, error) {
	repo, err := gitrepo.Clone(ctx, cvelistrepo.URLv5)
	if err != nil {
		return nil, nil, err
	}
	hc, err := gitrepo.HeadCommit(repo)
	if err != nil {
		return nil, nil, err
	}
	files, err := cvelistrepo.Files(repo, hc)
	if err != nil {
		return nil, nil, err
	}
	rc, err := report.NewDefaultClient(ctx)
	if err != nil {
		return nil, nil, err
	}

	var goCVEs, notGoCVEs []string
Categorize:
	for _, f := range files {
		for _, r := range rc.ReportsByAlias(f.ID()) {
			if r.Excluded != report.ExcludedNotGoCode {
				goCVEs = append(goCVEs, f.ID())
				continue Categorize
			}
		}
		notGoCVEs = append(notGoCVEs, f.ID())
	}

	numGo, numNotGo := n*3, n
	if len(goCVEs) <= numGo || len(notGoCVEs) <= numNotGo {
		return nil, nil, fmt.Errorf("not enough source CVEs to pick %d random values", numGo+numNotGo)
	}

	rand.Shuffle(len(goCVEs), func(i, j int) {
		goCVEs[i], goCVEs[j] = goCVEs[j], goCVEs[i]
	})
	rand.Shuffle(len(notGoCVEs), func(i, j int) {
		notGoCVEs[i], notGoCVEs[j] = notGoCVEs[j], notGoCVEs[i]
	})
	return goCVEs[:numGo], notGoCVEs[:numNotGo], nil
}

func writeLines(s []string, filename string) error {
	b := []byte(strings.Join(s, "\n"))
	return os.WriteFile(filename, b, 0666)
}
