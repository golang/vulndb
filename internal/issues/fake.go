// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package issues

import (
	"context"
	"fmt"
)

// NewFakeClient returns a fake Client suitable for testing.
func NewFakeClient() Client {
	return &fakeClient{
		nextID: 1,
		issues: map[int]*Issue{},
	}
}

type fakeClient struct {
	nextID int
	issues map[int]*Issue
}

func (c *fakeClient) Destination() string {
	return "in memory"
}

func (c *fakeClient) Reference(num int) string {
	return fmt.Sprintf("inMemory#%d", num)
}

func (c *fakeClient) GetIssue(_ context.Context, number int) (*Issue, error) {
	return &Issue{Title: "Hello"}, nil
}

func (c *fakeClient) IssueExists(_ context.Context, number int) (bool, error) {
	_, ok := c.issues[number]
	return ok, nil
}

func (c *fakeClient) CreateIssue(_ context.Context, iss *Issue) (number int, err error) {
	number = c.nextID
	c.nextID++
	copy := *iss
	c.issues[number] = &copy
	return number, nil
}
