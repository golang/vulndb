// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package store supports permanent data storage for the vuln worker.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-git/go-git/v5/plumbing/object"
	"golang.org/x/vulndb/internal/cve4"
	"golang.org/x/vulndb/internal/ghsa"
	"golang.org/x/vulndb/internal/report"
)

// A CVE4Record contains information about a v4 CVE.
type CVE4Record struct {
	// ID is the CVE ID, which is the same as the filename base. E.g. "CVE-2020-0034".
	ID string
	// Path is the path to the CVE file in the repo.
	Path string
	// Blobhash is the hash of the CVE's blob in repo, for quick change detection.
	BlobHash string
	// CommitHash is the commit of the cvelist repo from which this information came.
	CommitHash string
	// CommitTime is the time of the above commit.
	// If zero, it has not been populated.
	CommitTime time.Time
	// CVEState is the value of the metadata.STATE field.
	CVEState string
	// TriageState is the state of our triage processing on the CVE.
	TriageState TriageState
	// TriageStateReason is an explanation of TriageState.
	TriageStateReason string

	// Module is the Go module path that might be affected.
	Module string

	// Package is the Go package path that might be affected.
	Package string

	// CVE is a copy of the CVE, for the NeedsIssue triage state.
	CVE *cve4.CVE

	// ReferenceURLs is a list of the URLs in the CVE references,
	// for the FalsePositive triage state.
	ReferenceURLs []string

	// IssueReference is a reference to the GitHub issue that was filed.
	// E.g. golang/vulndb#12345.
	// Set only after a GitHub issue has been successfully created.
	IssueReference string

	// IssueCreatedAt is the time when the issue was created.
	// Set only after a GitHub issue has been successfully created.
	IssueCreatedAt time.Time

	// History holds previous states of a CVE4Record,
	// from most to least recent.
	History []*CVE4RecordSnapshot
}

func (r *CVE4Record) GetID() string                { return r.ID }
func (r *CVE4Record) GetUnit() string              { return r.Module }
func (r *CVE4Record) GetSource() report.Source     { return r.CVE }
func (r *CVE4Record) GetIssueReference() string    { return r.IssueReference }
func (r *CVE4Record) GetIssueCreatedAt() time.Time { return r.IssueCreatedAt }
func (r *CVE4Record) GetTriageState() TriageState  { return r.TriageState }

// Validate returns an error if the CVE4Record is not valid.
func (r *CVE4Record) Validate() error {
	if r.ID == "" {
		return errors.New("need ID")
	}
	if r.Path == "" {
		return errors.New("need Path")
	}
	if r.BlobHash == "" {
		return errors.New("need BlobHash")
	}
	if r.CommitHash == "" {
		return errors.New("need CommitHash")
	}
	if r.CommitTime.IsZero() {
		return errors.New("need CommitTime")
	}
	return r.TriageState.Validate()
}

// TriageState is the state of our work on the CVE or GHSA.
// It is implemented as a string rather than an int so that stored values are
// immune to renumbering.
type TriageState string

const (
	// No action is needed on the CVE or GHSA (perhaps because it is rejected, reserved or invalid).
	TriageStateNoActionNeeded TriageState = "NoActionNeeded"
	// The CVE needs to have an issue created.
	TriageStateNeedsIssue TriageState = "NeedsIssue"
	// An issue has been created in the issue tracker.
	// The IssueReference and IssueCreatedAt fields have more information.
	TriageStateIssueCreated TriageState = "IssueCreated"
	// This vulnerability has already been handled under an alias (i.e., a CVE
	// or GHSA that refers to the same vulnerability).
	TriageStateAlias TriageState = "Alias"
	// The CVE state was changed after the CVE was created.
	TriageStateUpdatedSinceIssueCreation TriageState = "UpdatedSinceIssueCreation"
	// Although the triager might think this CVE is relevant to Go, it is not.
	TriageStateFalsePositive TriageState = "FalsePositive"
	// There is already an entry in the Go vuln DB that covers this CVE.
	TriageStateHasVuln TriageState = "HasVuln"
)

// Validate returns an error if the TriageState is not one of the above values.
func (s TriageState) Validate() error {
	switch s {
	case TriageStateNoActionNeeded, TriageStateNeedsIssue, TriageStateIssueCreated, TriageStateAlias, TriageStateUpdatedSinceIssueCreation, TriageStateFalsePositive, TriageStateHasVuln:
		return nil
	default:
		return fmt.Errorf("bad TriageState %q", s)
	}
}

// NewCVE4Record creates a CVE4Record from a CVE, its path and its blob hash.
func NewCVE4Record(cve *cve4.CVE, path, blobHash string, commit *object.Commit) *CVE4Record {
	return &CVE4Record{
		ID:         cve.ID,
		CVEState:   cve.State,
		Path:       path,
		BlobHash:   blobHash,
		CommitHash: commit.Hash.String(),
		CommitTime: commit.Committer.When.In(time.UTC),
	}
}

// CVE4RecordSnapshot holds a previous state of a CVE4Record.
// The fields mean the same as those of CVE4Record.
type CVE4RecordSnapshot struct {
	CommitHash        string
	CVEState          string
	TriageState       TriageState
	TriageStateReason string
}

func (r *CVE4Record) Snapshot() *CVE4RecordSnapshot {
	return &CVE4RecordSnapshot{
		CommitHash:        r.CommitHash,
		CVEState:          r.CVEState,
		TriageState:       r.TriageState,
		TriageStateReason: r.TriageStateReason,
	}
}

// A CommitUpdateRecord describes a single update operation, which reconciles
// a commit in the CVE list repo with the DB state.
type CommitUpdateRecord struct {
	// The ID of this record in the DB. Needed to modify the record.
	ID string
	// When the update started and completed. If EndedAt is zero,
	// the update is in progress (or it crashed).
	StartedAt, EndedAt time.Time
	// The repo commit hash that this update is working on.
	CommitHash string
	// The time the commit occurred.
	CommitTime time.Time
	// The total number of CVEs being processed in this update.
	NumTotal int
	// The number currently processed. When this equals NumTotal, the
	// update is done.
	NumProcessed int
	// The number of CVEs added to the DB.
	NumAdded int
	// The number of CVEs modified.
	NumModified int
	// The error that stopped the update.
	Error string
	// The last time this record was updated.
	UpdatedAt time.Time `firestore:",serverTimestamp"`
}

// A LegacyGHSARecord holds information about a GitHub security advisory.
type LegacyGHSARecord struct {
	// GHSA is the advisory.
	GHSA *ghsa.SecurityAdvisory
	// TriageState is the state of our triage processing on the CVE.
	TriageState TriageState
	// TriageStateReason is an explanation of TriageState.
	TriageStateReason string
	// IssueReference is a reference to the GitHub issue that was filed.
	// E.g. golang/vulndb#12345.
	// Set only after a GitHub issue has been successfully created.
	IssueReference string
	// IssueCreatedAt is the time when the issue was created.
	// Set only after a GitHub issue has been successfully created.
	IssueCreatedAt time.Time
}

func (r *LegacyGHSARecord) GetID() string                { return r.GHSA.ID }
func (r *LegacyGHSARecord) GetUnit() string              { return r.GHSA.Vulns[0].Package }
func (r *LegacyGHSARecord) GetSource() report.Source     { return r.GHSA }
func (r *LegacyGHSARecord) GetIssueReference() string    { return r.IssueReference }
func (r *LegacyGHSARecord) GetIssueCreatedAt() time.Time { return r.IssueCreatedAt }
func (r *LegacyGHSARecord) GetTriageState() TriageState  { return r.TriageState }
func (r *LegacyGHSARecord) Validate() error              { return nil }

// A Store is a storage system for the CVE database.
type Store interface {
	// CreateCommitUpdateRecord creates a new CommitUpdateRecord. It should be called at the start
	// of an update. On successful return, the CommitUpdateRecord's ID field will be
	// set to a new, unique ID.
	CreateCommitUpdateRecord(context.Context, *CommitUpdateRecord) error

	// SetCommitUpdateRecord modifies the CommitUpdateRecord. Use the same record passed to
	// CreateCommitUpdateRecord, because it will have the correct ID.
	SetCommitUpdateRecord(context.Context, *CommitUpdateRecord) error

	// ListCommitUpdateRecords returns some of the CommitUpdateRecords in the store, from most to
	// least recent.
	ListCommitUpdateRecords(ctx context.Context, limit int) ([]*CommitUpdateRecord, error)

	// GetRecord returns the Record with the given id. If not found, it returns (nil, nil).
	GetRecord(ctx context.Context, id string) (Record, error)

	// ListCVE4RecordsWithTriageState returns all CVE4Records with the given triage state,
	// ordered by ID.
	ListCVE4RecordsWithTriageState(ctx context.Context, ts TriageState) ([]*CVE4Record, error)

	// GetDirectoryHash returns the hash for the tree object corresponding to dir.
	// If dir isn't found, it succeeds with the empty string.
	GetDirectoryHash(ctx context.Context, dir string) (string, error)

	// SetDirectoryHash sets the hash for the given directory.
	SetDirectoryHash(ctx context.Context, dir, hash string) error

	// RunTransaction runs the function in a transaction.
	RunTransaction(context.Context, func(context.Context, Transaction) error) error
}

// Transaction supports store operations that run inside a transaction.
type Transaction interface {
	// CreateRecord creates a new record.
	// It is an error if one with the same ID already exists.
	CreateRecord(Record) error

	// SetRecord sets the record in the database.
	// It is an error if no such record exists.
	SetRecord(Record) error

	// GetRecord returns a single record by ID.
	// If not found, it returns (nil, nil).
	GetRecord(id string) (Record, error)

	// GetRecords retrieves records for all CVE IDs between startID and
	// endID, inclusive.
	GetCVE4Records(startID, endID string) ([]*CVE4Record, error)

	// GetLegacyGHSARecords returns all the GHSARecords in the database.
	GetLegacyGHSARecords() ([]*LegacyGHSARecord, error)
}
