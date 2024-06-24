// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/tools/txtar"
	"golang.org/x/vulndb/cmd/vulnreport/log"
	"golang.org/x/vulndb/cmd/vulnreport/priority"
	"golang.org/x/vulndb/internal/gitrepo"
	"golang.org/x/vulndb/internal/proxy"
	"golang.org/x/vulndb/internal/test"
)

// go test ./cmd/vulnreport -update-test -proxy
var (
	testUpdate = flag.Bool("update-test", false, "(for test) whether to update test files")
	realProxy  = flag.Bool("proxy", false, "(for test) whether to use real proxy")
)

type testCase struct {
	name    string
	args    []string
	wantErr bool
}

type memWFS struct {
	written map[string][]byte
}

func newInMemoryWFS() *memWFS {
	return &memWFS{written: make(map[string][]byte)}
}

func (m *memWFS) WriteFile(fname string, b []byte) error {
	m.written[fname] = b
	return nil
}

func testFilename(t *testing.T) string {
	return filepath.Join("testdata", t.Name()+".txtar")
}

// TODO(tatianabradley): embed these test files.
const (
	testRepoFile     = "testdata/repo.txtar"
	testIssueTracker = "testdata/issue_tracker.txtar"
	testLegacyGHSAs  = "testdata/legacy_ghsas.txtar"
	testModuleMap    = "testdata/modules.csv"
)

// runTest runs the command on the test case in the default test environment.
func runTest(t *testing.T, cmd command, tc *testCase) {
	runTestWithEnv(t, cmd, tc, func(t *testing.T) (*environment, error) {
		return newTestEnv(t, testRepoFile, testIssueTracker, testLegacyGHSAs, testModuleMap)
	})
}

var testTime = time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC)

func newTestEnv(t *testing.T, reportRepoFile, issueTracker, legacyGHSAs, testModuleMap string) (*environment, error) {
	t.Helper()

	repo, err := gitrepo.ReadTxtarRepo(reportRepoFile, testTime)
	if err != nil {
		return nil, err
	}
	fsys, err := test.ReadTxtarFS(reportRepoFile)
	if err != nil {
		return nil, err
	}
	pc, err := proxy.NewTestClient(t, *realProxy)
	if err != nil {
		return nil, err
	}
	ic, err := newMemIC(issueTracker)
	if err != nil {
		return nil, err
	}
	gc, err := newMemGC(legacyGHSAs)
	if err != nil {
		return nil, err
	}
	mm, err := priority.CSVToMap(testModuleMap)
	if err != nil {
		return nil, err
	}
	return &environment{
		reportRepo: repo,
		reportFS:   fsys,
		pc:         pc,
		wfs:        newInMemoryWFS(),
		ic:         ic,
		gc:         gc,
		moduleMap:  mm,
	}, nil
}

func runTestWithEnv(t *testing.T, cmd command, tc *testCase, newEnv func(t *testing.T) (*environment, error)) {
	log.RemoveColor()
	t.Run(tc.name, func(t *testing.T) {
		// Re-generate a fresh env for each sub-test.
		env, err := newEnv(t)
		if err != nil {
			t.Error(err)
			return
		}
		out, logs := bytes.NewBuffer([]byte{}), bytes.NewBuffer([]byte{})
		log.WriteTo(out, logs)

		ctx := context.Background()
		err = run(ctx, cmd, tc.args, *env)
		if tc.wantErr {
			if err == nil {
				t.Errorf("run(%s, %s) = %v, want error", cmd.name(), tc.args, err)
			}
		} else if err != nil {
			t.Errorf("run(%s, %s) = %v, want no error", cmd.name(), tc.args, err)
		}

		got := &golden{out: out.Bytes(), logs: logs.Bytes()}
		if *testUpdate {
			comment := fmt.Sprintf("Expected output of test %s\ncommand: \"vulnreport %s %s\"", t.Name(), cmd.name(), strings.Join(tc.args, " "))
			var written map[string][]byte
			if env.wfs != nil {
				written = (env.wfs).(*memWFS).written
			}
			if err := writeGolden(t, got, comment, written); err != nil {
				t.Error(err)
				return
			}

		}

		want, err := readGolden(t)
		if err != nil {
			t.Errorf("could not read golden file: %v", err)
			return
		}
		if diff := cmp.Diff(want.String(), got.String()); diff != "" {
			t.Errorf("run(%s, %s) mismatch (-want, +got):\n%s", cmd.name(), tc.args, diff)
		}
	})
}

type golden struct {
	out  []byte
	logs []byte
}

func (g *golden) String() string {
	return fmt.Sprintf("out:\n%s\nlogs:\n%s", g.out, g.logs)
}

func readGolden(t *testing.T) (*golden, error) {
	fsys, err := test.ReadTxtarFS(testFilename(t))
	if err != nil {
		return nil, err
	}
	out, err := fs.ReadFile(fsys, "out")
	if err != nil {
		return nil, err
	}
	logs, err := fs.ReadFile(fsys, "logs")
	if err != nil {
		return nil, err
	}
	return &golden{out: out, logs: logs}, nil
}

func writeGolden(t *testing.T, g *golden, comment string, written map[string][]byte) error {
	files := []txtar.File{
		{Name: "out", Data: g.out},
		{Name: "logs", Data: g.logs},
	}
	for fname, b := range written {
		files = append(files, txtar.File{Name: fname, Data: b})
	}

	return test.WriteTxtar(testFilename(t), files, comment)
}
