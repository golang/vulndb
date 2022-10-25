// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package issues

import (
	"context"
	"fmt"

	"golang.org/x/exp/slices"
)

// NewFakeClient returns a fake Client suitable for testing.
func NewFakeClient() Client {
	return &fakeClient{
		nextID: 1,
		issues: map[int]*Issue{},
		labels: make(map[string][]int),
	}
}

type fakeClient struct {
	nextID int
	issues map[int]*Issue
	labels map[string][]int
}

func (c *fakeClient) Destination() string {
	return "in memory"
}

func (c *fakeClient) Reference(num int) string {
	return fmt.Sprintf("inMemory#%d", num)
}

func (c *fakeClient) GetIssue(_ context.Context, number int) (*Issue, error) {
	return c.issues[number], nil
}

func (c *fakeClient) IssueExists(_ context.Context, number int) (bool, error) {
	_, ok := c.issues[number]
	return ok, nil
}

func (c *fakeClient) CreateIssue(_ context.Context, iss *Issue) (number int, err error) {
	number = c.nextID
	c.nextID++
	iss.Number = number
	copy := *iss
	c.issues[number] = &copy
	if iss.Labels != nil {
		for _, label := range iss.Labels {
			c.labels[label] = append(c.labels[label], number)
		}
	}
	return number, nil
}

func (c *fakeClient) GetIssues(_ context.Context, opts GetIssuesOptions) ([]*Issue, error) {
	var issues []*Issue
	var issNums []int
	// get all labels from opts
	for _, label := range opts.Labels {
		issNums = append(issNums, c.labels[label]...)

	}
	slices.Sort(issNums)
	issNums = slices.Compact(issNums)
	for _, num := range issNums {
		issues = append(issues, c.issues[num])
	}

	return issues, nil
}
