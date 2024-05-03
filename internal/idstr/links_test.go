// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package idstr

import "testing"

func TestIsAdvisoryForOneOf(t *testing.T) {
	for _, tc := range []struct {
		name    string
		link    string
		aliases []string
		want    string
		wantOK  bool
	}{
		{
			name:    "ghsa_repo",
			link:    "https://github.com/42Atomys/stud42/security/advisories/GHSA-3hwm-922r-47hw",
			aliases: []string{"CVE-2020-0000", "GHSA-3hwm-922r-47hw"},
			want:    "GHSA-3hwm-922r-47hw",
			wantOK:  true,
		},
		{
			name:    "ghsa_global",
			link:    "https://github.com/advisories/GHSA-3hwm-922r-47hw",
			aliases: []string{"CVE-2020-0000", "GHSA-3hwm-922r-47hw"},
			want:    "GHSA-3hwm-922r-47hw",
			wantOK:  true,
		},
		{
			name:    "nist",
			link:    "https://nvd.nist.gov/vuln/detail/CVE-2020-0000",
			aliases: []string{"CVE-2020-0000", "GHSA-3hwm-922r-47hw"},
			want:    "CVE-2020-0000",
			wantOK:  true,
		},
		{
			name:    "mitre_legacy",
			link:    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-0000-0000/CVE-2020-0000",
			aliases: []string{"CVE-2020-0000", "GHSA-3hwm-922r-47hw"},
			want:    "CVE-2020-0000",
			wantOK:  true,
		},
		{
			name:    "mitre",
			link:    "https://www.cve.org/CVERecord?id=CVE-2020-0000",
			aliases: []string{"CVE-2020-0000", "GHSA-3hwm-922r-47hw"},
			want:    "CVE-2020-0000",
			wantOK:  true,
		},
		{
			name:    "not_advisory",
			link:    "https://example.com/GHSA-3hwm-922r-47hw",
			aliases: []string{"CVE-2020-0000", "GHSA-3hwm-922r-47hw"},
			want:    "",
			wantOK:  false,
		},
		{
			name:    "not_in_list",
			link:    "https://github.com/advisories/GHSA-3hwm-922r-47hw",
			aliases: []string{"CVE-2020-0000", "GHSA-cccc-yyyy-xxxx"},
			want:    "",
			wantOK:  false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, gotOK := IsAdvisoryForOneOf(tc.link, tc.aliases)
			if gotOK != tc.wantOK || got != tc.want {
				t.Errorf("IsAdvisoryForOneOf = (%q, %t) want (%q, %t)", got, gotOK, tc.want, tc.wantOK)
			}
		})
	}

}
