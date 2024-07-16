// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"cmp"
	"context"
	"fmt"
	"slices"

	"golang.org/x/exp/maps"
	"golang.org/x/tools/txtar"
	"golang.org/x/vulndb/internal/issues"
	"gopkg.in/yaml.v3"
)

type issueClient interface {
	Issues(context.Context, issues.IssuesOptions) ([]*issues.Issue, error)
	Issue(context.Context, int) (*issues.Issue, error)
	SetLabels(context.Context, int, []string) error
	Reference(int) string
}

var _ issueClient = &memIC{}

type memIC struct {
	is map[int]issues.Issue
}

func newMemIC(archive []byte) (*memIC, error) {
	ar := txtar.Parse(archive)
	m := &memIC{
		is: make(map[int]issues.Issue),
	}
	for _, f := range ar.Files {
		var iss issues.Issue
		if err := yaml.Unmarshal(f.Data, &iss); err != nil {
			return nil, err
		}
		m.is[iss.Number] = iss
	}
	return m, nil
}

func (m *memIC) Issue(_ context.Context, n int) (*issues.Issue, error) {
	if i, ok := m.is[n]; ok {
		return &i, nil
	}
	return nil, fmt.Errorf("issue %d not found", n)
}

func (m *memIC) Issues(_ context.Context, opts issues.IssuesOptions) (result []*issues.Issue, err error) {
	if len(opts.Labels) != 0 {
		return nil, fmt.Errorf("label option not supported for in-memory issues client")
	}
	all := maps.Values(m.is)
	slices.SortFunc(all, func(a, b issues.Issue) int { return cmp.Compare(a.Number, b.Number) })
	for _, i := range all {
		i := i
		if opts.State != "" && opts.State != i.State {
			continue
		}
		result = append(result, &i)
	}
	return result, nil
}

// TODO(tatianabradley): Write the modified issues to the test golden file.
func (m *memIC) SetLabels(_ context.Context, n int, labels []string) error {
	if iss, ok := m.is[n]; ok {
		iss.Labels = labels
		m.is[n] = iss
		return nil
	}

	return fmt.Errorf("issue %d not found", n)
}

func (*memIC) Reference(n int) string {
	return fmt.Sprintf("test-issue-tracker/%d", n)
}
