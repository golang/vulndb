// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cveutils

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/exp/slices"
)

// List returns the ids for all CVEs added or updated in the
// cvelistV5 repo at or after the given 'since' time.
//
// The value of "since" must be within the past month, because
// the CVEs are pulled from a log maintained by the CVE program
// which only contains updates from the past month.
func List(since time.Time) ([]string, error) {
	const deltaLogURL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json"
	return list(http.DefaultClient, deltaLogURL, since)
}

type deltaLog []*updateMeta

type updateMeta struct {
	FetchTime string     `json:"fetchTime"`
	New       []*cveMeta `json:"new,omitempty"`
	Updated   []*cveMeta `json:"updated,omitempty"`
}

type cveMeta struct {
	ID string `json:"cveId"`
	// The documentation isn't 100% clear, but this value appears to be
	// pulled directly from the CVE record field cveMetadata.dateUpdated.
	// The value cveMetadata.dateUpdated is changed when a
	// CNA makes an update to a CVE record, but not when MITRE makes an update
	// to the CVE that wasn't initiated by the CNA. As far as we are aware,
	// this only happens in cases where new references are added. For this reason,
	// CVEs that were considered updated a long time ago
	// can appear in the current delta log. (See for example CVE-2023-26035 in
	// testdata/deltaLog.txtar, which was last "updated" in Feb 2023 but appears
	// in the log for Nov-Dec 2023.)
	//
	// For purposes of the List function, we will consider this value (the CNA update time)
	// to be canonical. This is OK because references added by MITRE would not change
	// our triage decision about a CVE.
	Updated string `json:"dateUpdated"`
}

var errSinceTooEarly = errors.New("earliest entry in delta log is after since")

func list(c *http.Client, url string, since time.Time) ([]string, error) {
	b, err := fetch(c, url)
	if err != nil {
		return nil, err
	}

	var dl deltaLog
	if err := json.Unmarshal(b, &dl); err != nil {
		return nil, err
	}

	if earliest, err := dl.earliest(); err != nil {
		return nil, err
	} else if earliest.After(since) {
		return nil, fmt.Errorf("%w (earliest=%s, since=%s)", errSinceTooEarly, earliest, since)
	}

	var cves []string
	for _, um := range dl {
		fetched, err := parseTime(um.FetchTime)
		if err != nil {
			return nil, err
		}
		if fetched.Before(since) {
			continue
		}
		for _, c := range um.cves() {
			updated, err := parseTime(c.Updated)
			if err != nil {
				return nil, err
			}
			if updated.Before(since) {
				continue
			}
			cves = append(cves, c.ID)
		}
	}

	// Remove any duplicates.
	slices.Sort(cves)
	cves = slices.Compact(cves)

	return cves, nil
}

func fetch(c *http.Client, url string) ([]byte, error) {
	resp, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP GET %s returned non-OK status %s", url, resp.Status)
	}
	return io.ReadAll(resp.Body)
}

func parseTime(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		// Try adding a "Z" if the time string doesn't have one.
		if !strings.HasSuffix(s, "Z") {
			return time.Parse(time.RFC3339Nano, s+"Z")
		}
		return time.Time{}, err
	}
	return t, nil
}

func (um *updateMeta) cves() []*cveMeta {
	return append(slices.Clone(um.New), um.Updated...)
}

// earliest returns the earliest fetch time in the deltaLog,
// assuming the updateMeta entries are sorted from latest to earliest
// fetch time.
func (dl deltaLog) earliest() (time.Time, error) {
	last := dl[len(dl)-1]
	return parseTime(last.FetchTime)
}
