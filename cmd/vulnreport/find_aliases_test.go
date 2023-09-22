// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestAliasesBFS(t *testing.T) {
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
					return []string{"GHSA-1234567890"}, nil
				default:
					return nil, fmt.Errorf("unsupported alias %s", alias)
				}
			},
			want: []string{"CVE-2023-0001", "GHSA-1234567890"},
		},
		{
			knownAliases: []string{"CVE-2023-0001", "GHSA-1234567890"},
			aliasesFor: func(ctx context.Context, alias string) ([]string, error) {
				switch alias {
				case "CVE-2023-0001":
					return []string{"GHSA-1234567890"}, nil
				case "GHSA-1234567890":
					return []string{"CVE-2023-0001"}, nil
				default:
					return nil, fmt.Errorf("unsupported alias %s", alias)
				}
			},
			want: []string{"CVE-2023-0001", "GHSA-1234567890"},
		},
		{
			knownAliases: []string{"CVE-2023-0001", "GHSA-1234567890"},
			aliasesFor: func(ctx context.Context, alias string) ([]string, error) {
				switch alias {
				case "CVE-2023-0001":
					return []string{"GHSA-1234567890", "CVE-2023-0002"}, nil
				case "GHSA-1234567890":
					return []string{"CVE-2023-0001", "CVE-2023-0002"}, nil
				case "CVE-2023-0002":
					return []string{"CVE-2023-0001", "GHSA-1234567890"}, nil
				default:
					return nil, fmt.Errorf("unsupported alias %s", alias)
				}
			},
			want: []string{"CVE-2023-0001", "CVE-2023-0002", "GHSA-1234567890"},
		},
		{
			knownAliases: []string{"CVE-2023-0001"},
			aliasesFor: func(ctx context.Context, alias string) ([]string, error) {
				switch alias {
				case "CVE-2023-0001":
					return []string{"GHSA-1234567890"}, nil
				case "GHSA-1234567890":
					return []string{"CVE-2023-0002"}, nil
				case "CVE-2023-0002":
					return []string{"GHSA-1234567890"}, nil
				default:
					return nil, fmt.Errorf("unsupported alias %s", alias)
				}
			},
			want: []string{"CVE-2023-0001", "CVE-2023-0002", "GHSA-1234567890"},
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
		got := aliasesBFS(context.Background(), test.knownAliases, test.aliasesFor)
		if diff := cmp.Diff(test.want, got); diff != "" {
			t.Errorf("aliasesBFS(%v) = %v, want %v", test.knownAliases, got, test.want)
		}
	}
}
