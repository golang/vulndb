// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cve4

import (
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestDecodeCVE(t *testing.T) {
	for _, test := range []struct {
		name string
		json string
		want *CVE
	}{
		{"full 2017", json1, want1},
		{"LangString credit", json2, want2},
		{"CreditData credit", json3, want3},
	} {
		t.Run(test.name, func(t *testing.T) {
			var got *CVE
			if err := json.Unmarshal([]byte(test.json), &got); err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("mismatch (-want, +got):\n%s", diff)
			}
		})
	}
}

// A full CVE record from 2017, with a Credit field that is a list of strings.
const json1 = `
{
    "CVE_data_meta": {
        "ASSIGNER": "security@kubernetes.io",
        "DATE_ASSIGNED": "2017-12-06",
        "ID": "CVE-2017-1002101",
        "STATE": "PUBLIC"
    },
    "affects": {
        "vendor": {
            "vendor_data": [
                {
                    "product": {
                        "product_data": [
                            {
                                "product_name": "Kubernetes",
                                "version": {
                                    "version_data": [
                                        {
                                            "version_affected": "=",
                                            "version_value": "v1.3.x"
                                        },
                                        {
                                            "version_affected": "=",
                                            "version_value": "v1.4.x"
                                        },
                                        {
                                            "version_affected": "=",
                                            "version_value": "v1.5.x"
                                        },
                                        {
                                            "version_affected": "=",
                                            "version_value": "v1.6.x"
                                        },
                                        {
                                            "version_affected": "<",
                                            "version_value": "v1.7.14"
                                        },
                                        {
                                            "version_affected": "<",
                                            "version_value": "v1.8.9"
                                        },
                                        {
                                            "version_affected": "<",
                                            "version_value": "v1.9.4"
                                        }
                                    ]
                                }
                            }
                        ]
                    },
                    "vendor_name": "Kubernetes"
                }
            ]
        }
    },
    "credit": [
        "Reported by Maxim Ivanov"
    ],
    "data_format": "MITRE",
    "data_type": "CVE",
    "data_version": "4.0",
    "description": {
        "description_data": [
            {
                "lang": "eng",
                "value": "In Kubernetes versions 1.3.x, 1.4.x, 1.5.x, 1.6.x and prior to versions 1.7.14, 1.8.9 and 1.9.4 containers using subpath volume mounts with any volume type (including non-privileged pods, subject to file permissions) can access files/directories outside of the volume, including the host's filesystem."
            }
        ]
    },
    "impact": {
        "cvss": {
            "attackComplexity": "LOW",
            "attackVector": "NETWORK",
            "availabilityImpact": "HIGH",
            "baseScore": 8.8,
            "baseSeverity": "HIGH",
            "confidentialityImpact": "HIGH",
            "integrityImpact": "HIGH",
            "privilegesRequired": "LOW",
            "scope": "UNCHANGED",
            "userInteraction": "NONE",
            "vectorString": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            "version": "3.0"
        }
    },
    "problemtype": {
        "problemtype_data": [
            {
                "description": [
                    {
                        "lang": "eng",
                        "value": "handled symbolic links insecurely"
                    }
                ]
            }
        ]
    },
    "references": {
        "reference_data": [
            {
                "name": "RHSA-2018:0475",
                "refsource": "REDHAT",
                "url": "https://access.redhat.com/errata/RHSA-2018:0475"
            },
            {
                "name": "https://github.com/kubernetes/kubernetes/issues/60813",
                "refsource": "CONFIRM",
                "url": "https://github.com/kubernetes/kubernetes/issues/60813"
            },
            {
                "name": "https://github.com/bgeesaman/subpath-exploit/",
                "refsource": "MISC",
                "url": "https://github.com/bgeesaman/subpath-exploit/"
            },
            {
                "refsource": "SUSE",
                "name": "openSUSE-SU-2020:0554",
                "url": "http://lists.opensuse.org/opensuse-security-announce/2020-04/msg00041.html"
            }
        ]
    }
}
`

var want1 = &CVE{
	Metadata: Metadata{
		Assigner: "security@kubernetes.io",
		ID:       "CVE-2017-1002101",
		State:    "PUBLIC",
	},
	DataType:    "CVE",
	DataFormat:  "MITRE",
	DataVersion: "4.0",
	Affects: Affects{
		Vendor: Vendor{
			Data: []VendorDataItem{
				{
					VendorName: "Kubernetes",
					Product: Product{
						Data: []ProductDataItem{
							{
								ProductName: "Kubernetes",
								Version: VersionData{
									Data: []VersionDataItem{
										{VersionValue: "v1.3.x", VersionAffected: "="},
										{VersionValue: "v1.4.x", VersionAffected: "="},
										{VersionValue: "v1.5.x", VersionAffected: "="},
										{VersionValue: "v1.6.x", VersionAffected: "="},
										{VersionValue: "v1.7.14", VersionAffected: "<"},
										{VersionValue: "v1.8.9", VersionAffected: "<"},
										{VersionValue: "v1.9.4", VersionAffected: "<"},
									},
								},
							},
						},
					},
				},
			},
		},
	},
	Description: Description{
		Data: []LangString{
			{
				Lang:  "eng",
				Value: `In Kubernetes versions 1.3.x, 1.4.x, 1.5.x, 1.6.x and prior to versions 1.7.14, 1.8.9 and 1.9.4 containers using subpath volume mounts with any volume type (including non-privileged pods, subject to file permissions) can access files/directories outside of the volume, including the host's filesystem.`,
			},
		},
	},
	ProblemType: ProblemType{
		Data: []ProblemTypeDataItem{
			{Description: []LangString{
				{Lang: "eng", Value: "handled symbolic links insecurely"},
			}},
		},
	},
	References: References{
		Data: []Reference{
			{URL: "https://access.redhat.com/errata/RHSA-2018:0475"},
			{URL: "https://github.com/kubernetes/kubernetes/issues/60813"},
			{URL: "https://github.com/bgeesaman/subpath-exploit/"},
			{URL: "http://lists.opensuse.org/opensuse-security-announce/2020-04/msg00041.html"},
		},
	},
	Credit: Credit{
		Data: CreditData{
			Description: Description{
				Data: []LangString{{Lang: "eng", Value: "Reported by Maxim Ivanov"}},
			},
		},
	},
}

// A pared-down record, whose Credit field is a list of LangStrings.
const json2 = `
{
    "CVE_data_meta": {
        "ID": "CVE-2021-0204"
    },
    "credit": [
        {
            "lang": "eng",
            "value": "Juniper SIRT would like to acknowledge..."
        }
    ]
}
`

var want2 = &CVE{
	Metadata: Metadata{
		ID: "CVE-2021-0204",
	},
	Credit: Credit{
		Data: CreditData{
			Description: Description{
				Data: []LangString{{Lang: "eng", Value: "Juniper SIRT would like to acknowledge..."}},
			},
		},
	},
}

// Another simplified record, whose Credit field is a CreditData.
const json3 = `
{
    "CVE_data_meta": {
        "ID": "CVE-2021-28711"
    },
    "credit": {
        "credit_data": {
            "description": {
                "description_data": [
                    {
                        "lang": "eng",
                        "value": "This issue was discovered by..."
                    }
                ]
            }
        }
    }
}
`

var want3 = &CVE{
	Metadata: Metadata{
		ID: "CVE-2021-28711",
	},
	Credit: Credit{
		Data: CreditData{
			Description: Description{
				Data: []LangString{{Lang: "eng", Value: "This issue was discovered by..."}},
			},
		},
	},
}
