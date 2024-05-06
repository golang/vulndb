// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cve5

import (
	"context"
	"flag"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vulndb/internal/cvelistrepo"
	"golang.org/x/vulndb/internal/report"
)

var (
	updateTxtarRepo = flag.Bool("update-repo", false, "update the test repo (cvelist.txtar) with real CVE data - this takes a while")
	update          = flag.Bool("update", false, "update golden files")
	realProxy       = flag.Bool("proxy", false, "if true, contact the real module proxy and update expected responses")
)

var (
	testStdLibRecord = &CVERecord{
		DataType:    "CVE_RECORD",
		DataVersion: "5.0",
		Metadata: Metadata{
			ID: "CVE-9999-0001",
		},
		Containers: Containers{
			CNAContainer: CNAPublishedContainer{
				ProviderMetadata: ProviderMetadata{
					OrgID: GoOrgUUID,
				},
				Descriptions: []Description{
					{
						Lang:  "en",
						Value: `A description`,
					},
				},
				Affected: []Affected{
					{
						Vendor:        "Go standard library",
						Product:       "crypto/rand",
						CollectionURL: "https://pkg.go.dev",
						PackageName:   "crypto/rand",
						Versions: []VersionRange{
							{
								Introduced:  "0",
								Fixed:       "1.17.11",
								Status:      StatusAffected,
								VersionType: "semver",
							},
							{
								Introduced:  "1.18.0",
								Fixed:       "1.18.3",
								Status:      StatusAffected,
								VersionType: "semver",
							},
						},
						Platforms: []string{
							"windows",
						},
						ProgramRoutines: []ProgramRoutine{
							{
								Name: "TestSymbol",
							},
						},
						DefaultStatus: StatusUnaffected,
					},
				},
				ProblemTypes: []ProblemType{
					{
						Descriptions: []ProblemTypeDescription{
							{
								Lang:        "en",
								Description: "CWE-835: Loop with Unreachable Exit Condition ('Infinite Loop')",
							},
						},
					},
				},
				References: []Reference{
					{
						URL: "https://go.dev/cl/12345",
					},
					{
						URL: "https://go.googlesource.com/go/+/abcde",
					},
					{
						URL: "https://go.dev/issue/12345",
					},
					{
						URL: "https://groups.google.com/g/golang-announce/c/abcdef",
					},
					{
						// This normally reports in the format .../vuln/GO-YYYY-XXXX, but our logic
						// relies on file path so this "abnormal" formatting is so that tests pass.
						URL: "https://pkg.go.dev/vuln/std-report",
					},
				},
				Credits: []Credit{
					{
						Lang:  "en",
						Value: "A Credit",
					},
				},
			},
		},
	}
	testThirdPartyRecord = &CVERecord{
		DataType:    "CVE_RECORD",
		DataVersion: "5.0",
		Metadata: Metadata{
			ID: "CVE-9999-0001",
		},
		Containers: Containers{
			CNAContainer: CNAPublishedContainer{
				ProviderMetadata: ProviderMetadata{
					OrgID: GoOrgUUID,
				},
				Descriptions: []Description{
					{
						Lang:  "en",
						Value: `Unsanitized input in the default logger in github.com/gin-gonic/gin before v1.6.0 allows remote attackers to inject arbitrary log lines.`,
					},
				},
				Affected: []Affected{
					{
						Vendor:        "github.com/gin-gonic/gin",
						Product:       "github.com/gin-gonic/gin",
						CollectionURL: "https://pkg.go.dev",
						PackageName:   "github.com/gin-gonic/gin",
						Versions: []VersionRange{
							{
								Introduced:  "0",
								Fixed:       "1.6.0",
								Status:      StatusAffected,
								VersionType: "semver",
							},
						},
						ProgramRoutines: []ProgramRoutine{
							{
								Name: "defaultLogFormatter",
							},
						},
						DefaultStatus: StatusUnaffected,
					},
				},
				ProblemTypes: []ProblemType{
					{
						Descriptions: []ProblemTypeDescription{
							{
								Lang:        "en",
								Description: "CWE-20: Improper Input Validation",
							},
						},
					},
				},
				References: []Reference{
					{
						URL: "https://github.com/gin-gonic/gin/pull/2237",
					},
					{
						URL: "https://github.com/gin-gonic/gin/commit/a71af9c144f9579f6dbe945341c1df37aaf09c0d",
					},
					{
						// This normally reports in the format .../vuln/GO-YYYY-XXXX, but our logic
						// relies on file path so this "abnormal" formatting is so that tests pass.
						URL: "https://pkg.go.dev/vuln/report",
					},
				},
				Credits: []Credit{
					{
						Lang:  "en",
						Value: "@thinkerou <thinkerou@gmail.com>",
					},
				},
			},
		},
	}
	testNoVersionsRecord = &CVERecord{
		DataType:    "CVE_RECORD",
		DataVersion: "5.0",
		Metadata: Metadata{
			ID: "CVE-9999-0001",
		},
		Containers: Containers{
			CNAContainer: CNAPublishedContainer{
				ProviderMetadata: ProviderMetadata{
					OrgID: GoOrgUUID,
				},
				Descriptions: []Description{
					{
						Lang:  "en",
						Value: `Unsanitized input in the default logger in github.com/gin-gonic/gin before v1.6.0 allows remote attackers to inject arbitrary log lines.`,
					},
				},
				Affected: []Affected{
					{
						Vendor:        "github.com/gin-gonic/gin",
						Product:       "github.com/gin-gonic/gin",
						CollectionURL: "https://pkg.go.dev",
						PackageName:   "github.com/gin-gonic/gin",
						Versions:      nil,
						ProgramRoutines: []ProgramRoutine{
							{
								Name: "defaultLogFormatter",
							},
						},
						DefaultStatus: StatusAffected,
					},
				},
				ProblemTypes: []ProblemType{
					{
						Descriptions: []ProblemTypeDescription{
							{
								Lang:        "en",
								Description: "CWE-20: Improper Input Validation",
							},
						},
					},
				},
				References: []Reference{
					{
						URL: "https://github.com/gin-gonic/gin/pull/2237",
					},
					{
						URL: "https://github.com/gin-gonic/gin/commit/a71af9c144f9579f6dbe945341c1df37aaf09c0d",
					},
					{
						// This normally reports in the format .../vuln/GO-YYYY-XXXX, but our logic
						// relies on file path so this "abnormal" formatting is so that tests pass.
						URL: "https://pkg.go.dev/vuln/no-versions",
					},
				},
				Credits: []Credit{
					{
						Lang:  "en",
						Value: "@thinkerou <thinkerou@gmail.com>",
					},
				},
			},
		},
	}
)

func TestFromReport(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		want     *CVERecord
	}{
		{
			name:     "Standard Library Report",
			filename: "testdata/std-report.yaml",
			want:     testStdLibRecord,
		},
		{
			name:     "Third Party Report",
			filename: "testdata/report.yaml",
			want:     testThirdPartyRecord,
		},
		{
			name:     "No Versions Report",
			filename: "testdata/no-versions.yaml",
			want:     testNoVersionsRecord,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r, err := report.Read(test.filename)
			if err != nil {
				t.Fatal(err)
			}
			got, err := FromReport(r)
			if err != nil {
				t.Fatalf("FromReport() failed unexpectedly; err=%v", err)
			}
			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Fatalf("FromReport(): unexpected diffs (-want,+got):\n%v", diff)
			}
		})
	}
}

func TestVersionRangeToVersionRange(t *testing.T) {
	tests := []struct {
		name        string
		versions    []report.VersionRange
		wantRange   []VersionRange
		wantDefault VersionStatus
	}{
		{
			name:        "nil",
			versions:    nil,
			wantRange:   nil,
			wantDefault: StatusAffected,
		},
		{
			name:        "empty",
			versions:    []report.VersionRange{},
			wantRange:   nil,
			wantDefault: StatusAffected,
		},
		{
			name: "basic",
			versions: []report.VersionRange{
				{
					Introduced: "1.0.0",
					Fixed:      "1.0.1",
				},
				{
					Introduced: "1.2.0",
					Fixed:      "1.2.3",
				},
			},
			wantRange: []VersionRange{
				{
					Introduced:  "1.0.0",
					Fixed:       "1.0.1",
					Status:      StatusAffected,
					VersionType: typeSemver,
				},
				{
					Introduced:  "1.2.0",
					Fixed:       "1.2.3",
					Status:      StatusAffected,
					VersionType: typeSemver,
				},
			},
			wantDefault: StatusUnaffected,
		},
		{
			name: "no initial introduced",
			versions: []report.VersionRange{
				{
					Fixed: "1.0.1",
				},
				{
					Introduced: "1.2.0",
					Fixed:      "1.2.3",
				},
			},
			wantRange: []VersionRange{
				{
					Introduced:  "0",
					Fixed:       "1.0.1",
					Status:      StatusAffected,
					VersionType: typeSemver,
				},
				{
					Introduced:  "1.2.0",
					Fixed:       "1.2.3",
					Status:      StatusAffected,
					VersionType: typeSemver,
				},
			},
			wantDefault: StatusUnaffected,
		},
		{
			name: "no fix",
			versions: []report.VersionRange{
				{
					Introduced: "1.0.0",
				},
			},
			wantRange: []VersionRange{
				{
					Introduced:  "0",
					Fixed:       "1.0.0",
					Status:      StatusUnaffected,
					VersionType: typeSemver,
				},
			},
			wantDefault: StatusAffected,
		},
		{
			name: "no final fix",
			versions: []report.VersionRange{
				{
					Introduced: "1.0.0",
					Fixed:      "1.0.3",
				},
				{
					Introduced: "1.1.0",
				},
			},
			wantRange: []VersionRange{
				{
					Introduced:  "0",
					Fixed:       "1.0.0",
					Status:      StatusUnaffected,
					VersionType: typeSemver,
				},
				{
					Introduced:  "1.0.3",
					Fixed:       "1.1.0",
					Status:      StatusUnaffected,
					VersionType: typeSemver,
				},
			},
			wantDefault: StatusAffected,
		},
		{
			name: "no initial introduced and no final fix",
			versions: []report.VersionRange{
				{
					Fixed: "1.0.3",
				},
				{
					Introduced: "1.0.5",
					Fixed:      "1.0.7",
				},
				{
					Introduced: "1.1.0",
				},
			},
			wantRange: []VersionRange{
				{
					Introduced:  "1.0.3",
					Fixed:       "1.0.5",
					Status:      StatusUnaffected,
					VersionType: typeSemver,
				},
				{
					Introduced:  "1.0.7",
					Fixed:       "1.1.0",
					Status:      StatusUnaffected,
					VersionType: typeSemver,
				},
			},
			wantDefault: StatusAffected,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRange, gotStatus := versionRangeToVersionRange(tt.versions)
			if !reflect.DeepEqual(gotRange, tt.wantRange) {
				t.Errorf("versionRangeToVersionRange() got version range = %v, want %v", gotRange, tt.wantRange)
			}
			if !reflect.DeepEqual(gotStatus, tt.wantDefault) {
				t.Errorf("versionRangeToVersionRange() got default status = %v, want %v", gotStatus, tt.wantDefault)
			}
		})
	}
}

func TestToReport(t *testing.T) {
	if *updateTxtarRepo {
		cvelistrepo.UpdateTxtar(context.Background(), t, cvelistrepo.URLv5)
	}

	if err := cvelistrepo.TestToReport[*CVERecord](t, *update, *realProxy); err != nil {
		t.Fatal(err)
	}
}
