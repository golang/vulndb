// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vulndb/cmd/vulnreport/log"
)

func TestAliasesBFS(t *testing.T) {
	log.Discard()
	tests := []struct {
		knownAliases []string
		aliasesFor   func(ctx context.Context, alias string) ([]string, error)
		want         []string
	}{
		{
			knownAliases: []string{"CVE-2023-0001"},
			aliasesFor: func(ctx context.Context, alias string) ([]string, error) {
				switch alias {
				case "CVE-2023-0001":
					return []string{"GHSA-xxxx-yyyy-zzzz"}, nil
				default:
					return nil, errBadAlias(t, alias)
				}
			},
			want: []string{"CVE-2023-0001", "GHSA-xxxx-yyyy-zzzz"},
		},
		{
			knownAliases: []string{"CVE-2023-0001", "GHSA-xxxx-yyyy-zzzz"},
			aliasesFor: func(ctx context.Context, alias string) ([]string, error) {
				switch alias {
				case "CVE-2023-0001":
					return []string{"GHSA-xxxx-yyyy-zzzz"}, nil
				case "GHSA-xxxx-yyyy-zzzz":
					return []string{"CVE-2023-0001"}, nil
				default:
					return nil, errBadAlias(t, alias)
				}
			},
			want: []string{"CVE-2023-0001", "GHSA-xxxx-yyyy-zzzz"},
		},
		{
			knownAliases: []string{"CVE-2023-0001", "GHSA-xxxx-yyyy-zzzz"},
			aliasesFor: func(ctx context.Context, alias string) ([]string, error) {
				switch alias {
				case "CVE-2023-0001":
					return []string{"GHSA-xxxx-yyyy-zzzz", "CVE-2023-0002"}, nil
				case "GHSA-xxxx-yyyy-zzzz":
					return []string{"CVE-2023-0001", "CVE-2023-0002"}, nil
				case "CVE-2023-0002":
					return []string{"CVE-2023-0001", "GHSA-xxxx-yyyy-zzzz"}, nil
				default:
					return nil, errBadAlias(t, alias)
				}
			},
			want: []string{"CVE-2023-0001", "CVE-2023-0002", "GHSA-xxxx-yyyy-zzzz"},
		},
		{
			knownAliases: []string{"CVE-2023-0001"},
			aliasesFor: func(ctx context.Context, alias string) ([]string, error) {
				switch alias {
				case "CVE-2023-0001":
					return []string{"GHSA-xxxx-yyyy-zzzz"}, nil
				case "GHSA-xxxx-yyyy-zzzz":
					return []string{"CVE-2023-0002"}, nil
				case "CVE-2023-0002":
					return []string{"GHSA-xxxx-yyyy-zzzz"}, nil
				default:
					return nil, errBadAlias(t, alias)
				}
			},
			want: []string{"CVE-2023-0001", "CVE-2023-0002", "GHSA-xxxx-yyyy-zzzz"},
		},
		{
			knownAliases: []string{},
			aliasesFor: func(ctx context.Context, alias string) ([]string, error) {
				return nil, fmt.Errorf("unsupported alias %s", alias)
			},
			want: nil,
		},
	}

	for _, test := range tests {
		t.Run(strings.Join(test.knownAliases, ","), func(t *testing.T) {
			got := aliasesBFS(context.Background(), test.knownAliases, test.aliasesFor)
			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("aliasesBFS(%v) = %v, want %v", test.knownAliases, got, test.want)
			}
		})
	}
}

func errBadAlias(t *testing.T, alias string) error {
	t.Helper()
	t.Logf("alias %s not found", alias)
	return fmt.Errorf("bad alias %s", alias)
}
