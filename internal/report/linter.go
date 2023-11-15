// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import (
	"fmt"
	"sync"
)

type linter struct {
	prefix string

	mu     sync.Mutex // protects errors and groups
	errors []string
	groups []*linter
}

// NewLinter creates a new linter.
// If prefix is set, all lints will have the given prefix
// when Errors is called.
func NewLinter(prefix string) *linter {
	return &linter{
		prefix: prefix,
		groups: make([]*linter, 0),
	}
}

// Group adds a new lint group to the linter and returns
// a pointer to it.
// If prefix is set, all lints in the group will have the given prefix
// when Errors is called.
func (l *linter) Group(prefix string) *linter {
	l.mu.Lock()
	defer l.mu.Unlock()

	g := NewLinter(prefix)
	l.groups = append(l.groups, g)
	return g
}

// Error adds a new lint.
func (l *linter) Error(a ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()

	var s = fmt.Sprint(a...)
	l.errors = append(l.errors, s)
}

// Errorf adds a new formatted lint.
func (l *linter) Errorf(format string, a ...any) {
	l.Error(fmt.Sprintf(format, a...))
}

// Errors returns all the lints added to the linter
// and its groups so far, formatted as strings.
func (l *linter) Errors() []string {
	l.mu.Lock()
	defer l.mu.Unlock()

	result := make([]string, 0, len(l.errors))
	addErrs := func(errs []string) {
		for _, err := range errs {
			if l.prefix != "" {
				err = fmt.Sprintf("%s: %s", l.prefix, err)
			}
			result = append(result, err)
		}
	}

	addErrs(l.errors)
	for _, g := range l.groups {
		addErrs(g.Errors())
	}

	return result
}
