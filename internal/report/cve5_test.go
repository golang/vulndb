// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vulndb/internal/cveschema5"
)

var (
	testStdLibRecord = &cveschema5.CVERecord{
		DataType:    "CVE_RECORD",
		DataVersion: "5.0",
		Metadata: cveschema5.Metadata{
			ID: "CVE-9999-0001",
		},
		Containers: cveschema5.Containers{
			CNAContainer: cveschema5.CNAPublishedContainer{
				ProviderMetadata: cveschema5.ProviderMetadata{
					OrgID: GoOrgUUID,
				},
				Descriptions: []cveschema5.Description{
					{
						Lang:  "en",
						Value: `A description`,
					},
				},
				Affected: []cveschema5.Affected{
					{
						Vendor:        "Go standard library",
						Product:       "crypto/rand",
						CollectionURL: "https://pkg.go.dev",
						PackageName:   "crypto/rand",
						Versions: []cveschema5.VersionRange{
							{
								Introduced:  "0",
								Fixed:       "1.17.11",
								Status:      cveschema5.StatusAffected,
								VersionType: "semver",
							},
							{
								Introduced:  "1.18.0",
								Fixed:       "1.18.3",
								Status:      cveschema5.StatusAffected,
								VersionType: "semver",
							},
						},
						Platforms: []string{
							"windows",
						},
						ProgramRoutines: []cveschema5.ProgramRoutine{
							{
								Name: "TestSymbol",
							},
						},
						DefaultStatus: cveschema5.StatusUnaffected,
					},
				},
				ProblemTypes: []cveschema5.ProblemType{
					{
						Descriptions: []cveschema5.ProblemTypeDescription{
							{
								Lang:        "en",
								Description: "CWE-835: Loop with Unreachable Exit Condition ('Infinite Loop')",
							},
						},
					},
				},
				References: []cveschema5.Reference{
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
				Credits: []cveschema5.Credit{
					{
						Lang:  "en",
						Value: "A Credit",
					},
				},
			},
		},
	}
	testThirdPartyRecord = &cveschema5.CVERecord{
		DataType:    "CVE_RECORD",
		DataVersion: "5.0",
		Metadata: cveschema5.Metadata{
			ID: "CVE-9999-0001",
		},
		Containers: cveschema5.Containers{
			CNAContainer: cveschema5.CNAPublishedContainer{
				ProviderMetadata: cveschema5.ProviderMetadata{
					OrgID: GoOrgUUID,
				},
				Descriptions: []cveschema5.Description{
					{
						Lang:  "en",
						Value: `Unsanitized input in the default logger in github.com/gin-gonic/gin before v1.6.0 allows remote attackers to inject arbitrary log lines.`,
					},
				},
				Affected: []cveschema5.Affected{
					{
						Vendor:        "github.com/gin-gonic/gin",
						Product:       "github.com/gin-gonic/gin",
						CollectionURL: "https://pkg.go.dev",
						PackageName:   "github.com/gin-gonic/gin",
						Versions: []cveschema5.VersionRange{
							{
								Introduced:  "0",
								Fixed:       "1.6.0",
								Status:      cveschema5.StatusAffected,
								VersionType: "semver",
							},
						},
						ProgramRoutines: []cveschema5.ProgramRoutine{
							{
								Name: "defaultLogFormatter",
							},
						},
						DefaultStatus: cveschema5.StatusUnaffected,
					},
				},
				ProblemTypes: []cveschema5.ProblemType{
					{
						Descriptions: []cveschema5.ProblemTypeDescription{
							{
								Lang:        "en",
								Description: "CWE-20: Improper Input Validation",
							},
						},
					},
				},
				References: []cveschema5.Reference{
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
				Credits: []cveschema5.Credit{
					{
						Lang:  "en",
						Value: "@thinkerou <thinkerou@gmail.com>",
					},
				},
			},
		},
	}
	testNoVersionsRecord = &cveschema5.CVERecord{
		DataType:    "CVE_RECORD",
		DataVersion: "5.0",
		Metadata: cveschema5.Metadata{
			ID: "CVE-9999-0001",
		},
		Containers: cveschema5.Containers{
			CNAContainer: cveschema5.CNAPublishedContainer{
				ProviderMetadata: cveschema5.ProviderMetadata{
					OrgID: GoOrgUUID,
				},
				Descriptions: []cveschema5.Description{
					{
						Lang:  "en",
						Value: `Unsanitized input in the default logger in github.com/gin-gonic/gin before v1.6.0 allows remote attackers to inject arbitrary log lines.`,
					},
				},
				Affected: []cveschema5.Affected{
					{
						Vendor:        "github.com/gin-gonic/gin",
						Product:       "github.com/gin-gonic/gin",
						CollectionURL: "https://pkg.go.dev",
						PackageName:   "github.com/gin-gonic/gin",
						Versions:      nil,
						ProgramRoutines: []cveschema5.ProgramRoutine{
							{
								Name: "defaultLogFormatter",
							},
						},
						DefaultStatus: cveschema5.StatusAffected,
					},
				},
				ProblemTypes: []cveschema5.ProblemType{
					{
						Descriptions: []cveschema5.ProblemTypeDescription{
							{
								Lang:        "en",
								Description: "CWE-20: Improper Input Validation",
							},
						},
					},
				},
				References: []cveschema5.Reference{
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
				Credits: []cveschema5.Credit{
					{
						Lang:  "en",
						Value: "@thinkerou <thinkerou@gmail.com>",
					},
				},
			},
		},
	}
)

func TestToCVE5(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		want     *cveschema5.CVERecord
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
			r, err := Read(test.filename)
			if err != nil {
				t.Fatal(err)
			}
			got, err := r.ToCVE5()
			if err != nil {
				t.Fatalf("ToCVE5() failed unexpectedly; err=%v", err)
			}
			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Fatalf("ToCVE5(): unexpected diffs (-want,+got):\n%v", diff)
			}
		})
	}
}

func TestCVEFilename(t *testing.T) {
	want := "data/cve/v5/GO-1999-0001.json"
	r := &Report{ID: "GO-1999-0001"}
	if got := r.CVEFilename(); got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}
