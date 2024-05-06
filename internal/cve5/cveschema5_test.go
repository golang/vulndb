// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cve5

import (
	"reflect"
	"testing"
)

var basicExampleRecord = &CVERecord{
	DataType:    "CVE_RECORD",
	DataVersion: "5.0",
	Metadata: Metadata{
		ID:    "CVE-2022-0000",
		OrgID: "b3476cb9-2e3d-41a6-98d0-0f47421a65b6",
		State: StatePublished,
	},
	Containers: Containers{
		CNAContainer: CNAPublishedContainer{
			ProviderMetadata: ProviderMetadata{
				OrgID: "b3476cb9-2e3d-41a6-98d0-0f47421a65b6",
			},
			ProblemTypes: []ProblemType{
				{
					Descriptions: []ProblemTypeDescription{
						{
							Lang:        "en",
							Description: "CWE-78 OS Command Injection",
						},
					},
				},
			},
			Descriptions: []Description{
				{
					Lang:  "en",
					Value: "OS Command Injection vulnerability parseFilename function of example.php in the Web Management Interface of Example.org Example Enterprise on Windows, MacOS and XT-4500 allows remote unauthenticated attackers to escalate privileges.\n\nThis issue affects:\n  *  1.0 versions before 1.0.6\n  *  2.1 versions from 2.16 until 2.1.9.",
				},
			},
			Affected: []Affected{
				{
					Vendor:  "Example.org",
					Product: "Example Enterprise",
					Versions: []VersionRange{
						{
							Introduced:  "1.0.0",
							Fixed:       "1.0.6",
							Status:      StatusAffected,
							VersionType: "semver",
						},
					},
					DefaultStatus: StatusUnaffected,
				},
			},
			References: []Reference{
				{
					URL: "https://example.org/ESA-22-11-CVE-2022-0000",
				},
			},
		},
	},
}

func TestRead(t *testing.T) {
	f := "testdata/basic_example.json"
	record, err := Read("testdata/basic-example.json")
	if err != nil {
		t.Fatalf("Read(%s) failed unexpectedly; err=%v", f, err)
	}
	if got, want := record, basicExampleRecord; !reflect.DeepEqual(got, want) {
		t.Errorf("Read(%s) = %v\n want %v", f, got, want)
	}
}
