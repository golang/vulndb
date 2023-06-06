// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package cveschema5 contains the schema for a CVE Record in CVE JSON 5.0
// format. The package implements a subset of the schema needed to
// publish reports for the vulnerability database.
//
// https://github.com/CVEProject/cve-schema/blob/master/schema/v5.0/CVE_JSON_5.0_schema.json
// contains the full JSON schema and documentation for each field.
package cveschema5

import (
	"encoding/json"
	"os"
)

type CVERecord struct {
	DataType    string     `json:"dataType"`
	DataVersion string     `json:"dataVersion"`
	Metadata    Metadata   `json:"cveMetadata"`
	Containers  Containers `json:"containers"`
}

type State string

const (
	StateReserved  State = "RESERVED"
	StatePublished State = "PUBLISHED"
	StateRejected  State = "REJECTED"
)

type Metadata struct {
	ID     string `json:"cveId"`
	OrgID  string `json:"assignerOrgId,omitempty"`
	Serial int    `json:"serial,omitempty"`
	State  State  `json:"state,omitempty"`
}

type Containers struct {
	CNAContainer CNAPublishedContainer `json:"cna"`
}

type CNAPublishedContainer struct {
	ProviderMetadata ProviderMetadata `json:"providerMetadata"`
	Title            string           `json:"title,omitempty"`
	Descriptions     []Description    `json:"descriptions"`
	Affected         []Affected       `json:"affected"`
	ProblemTypes     []ProblemType    `json:"problemTypes,omitempty"`
	References       []Reference      `json:"references"`
	Credits          []Credit         `json:"credits,omitempty"`
}

type ProviderMetadata struct {
	OrgID string `json:"orgId"`
}

type Description struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type Affected struct {
	Vendor          string           `json:"vendor,omitempty"`
	Product         string           `json:"product,omitempty"`
	CollectionURL   string           `json:"collectionURL,omitempty"`
	PackageName     string           `json:"packageName,omitempty"`
	Versions        []VersionRange   `json:"versions,omitempty"`
	Platforms       []string         `json:"platforms,omitempty"`
	ProgramRoutines []ProgramRoutine `json:"programRoutines,omitempty"`
	DefaultStatus   VersionStatus    `json:"defaultStatus,omitempty"`
}

type ProblemType struct {
	Descriptions []ProblemTypeDescription `json:"descriptions"`
}

type ProblemTypeDescription struct {
	Lang        string `json:"lang"`
	Description string `json:"description"`
}

type Reference struct {
	URL string `json:"url"`
}

type Credit struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type VersionRange struct {
	Introduced  Version       `json:"version"`
	Fixed       Version       `json:"lessThan"`
	Status      VersionStatus `json:"status"`
	VersionType string        `json:"versionType"`
}

type VersionStatus string

const (
	StatusAffected   VersionStatus = "affected"
	StatusUnaffected VersionStatus = "unaffected"
	StatusUnknown    VersionStatus = "unknown"
)

type Version string

type ProgramRoutine struct {
	Name string `json:"name"`
}

// Read unmarshals the JSON CVE Record in `filename` into a CVE Record.
func Read(filename string) (*CVERecord, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var record CVERecord
	err = json.Unmarshal(b, &record)
	if err != nil {
		return nil, err
	}
	return &record, nil
}

// ReadForPublish reads the portion of a CVE record that can be published
// via the CVE Services API from filename.
func ReadForPublish(filename string) (cveID string, toPublish *Containers, err error) {
	record, err := Read(filename)
	if err != nil {
		return "", nil, err
	}
	return record.Metadata.ID, &record.Containers, nil
}
