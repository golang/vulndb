// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"golang.org/x/vulndb/internal/cve4"
	"golang.org/x/vulndb/internal/cvelistrepo"
	"golang.org/x/vulndb/internal/cveutils"
	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/ghsa"
	"golang.org/x/vulndb/internal/observe"
	"golang.org/x/vulndb/internal/report"
	"golang.org/x/vulndb/internal/worker/log"
	"golang.org/x/vulndb/internal/worker/store"
)

// A triageFunc triages a CVE: it decides whether an issue needs to be filed.
// If so, it returns a non-empty string indicating the possibly
// affected module.
type triageFunc func(*cve4.CVE) (*cveutils.TriageResult, error)

// A cveUpdater performs an update operation on the DB.
type cveUpdater struct {
	repo           *git.Repository
	commit         *object.Commit
	st             store.Store
	rc             *report.Client
	affectedModule triageFunc
}

type updateStats struct {
	skipped                             bool // directory skipped because hashes match
	numProcessed, numAdded, numModified int
}

// newCVEUpdater creates an updater for updating the store with information from
// the repo commit.
// needsIssue determines whether a CVE needs an issue to be filed for it.
func newCVEUpdater(repo *git.Repository, commit *object.Commit, st store.Store, rc *report.Client, needsIssue triageFunc) *cveUpdater {
	u := &cveUpdater{
		repo:           repo,
		commit:         commit,
		st:             st,
		rc:             rc,
		affectedModule: needsIssue,
	}
	return u
}

// update updates the DB to match the repo at the given commit.
// It also triages new or changed issues.
func (u *cveUpdater) update(ctx context.Context) (ur *store.CommitUpdateRecord, err error) {
	// We want the action of reading the old DB record, updating it and
	// writing it back to be atomic. It would be too expensive to do that one
	// record at a time. Ideally we'd process the whole repo commit in one
	// transaction, but Firestore has a limit on how many writes one
	// transaction can do, so the CVE files in the repo are processed in
	// batches, one transaction per batch.
	defer derrors.Wrap(&err, "cveUpdater.update(%s)", u.commit.Hash)
	ctx, span := observe.Start(ctx, "cveUpdater.update")
	defer span.End()

	defer func() {
		if err == nil {
			var nAdded, nModified int64
			if ur != nil {
				nAdded = int64(ur.NumAdded)
				nModified = int64(ur.NumModified)
			}
			log.Infof(ctx, "CVE Firestore update succeeded on CVE list repo hash=%s: added %d, modified %d",
				u.commit.Hash, nAdded, nModified)
		}
	}()

	log.Infof(ctx, "CVE Firestore update starting on CVE list repo hash=%s", u.commit.Hash)

	// Get all the CVE files.
	// It is cheaper to read all the files from the repo and compare
	// them to the DB in bulk, than to walk the repo and process
	// each file individually.
	files, err := cvelistrepo.Files(u.repo, u.commit)
	if err != nil {
		return nil, err
	}
	// Process files in the same directory together, so we can easily skip
	// the entire directory if it hasn't changed.
	filesByDir, err := groupFilesByDirectory(files)
	if err != nil {
		return nil, err
	}

	// Create a new CommitUpdateRecord to describe this run of doUpdate.
	ur = &store.CommitUpdateRecord{
		StartedAt:  time.Now(),
		CommitHash: u.commit.Hash.String(),
		CommitTime: u.commit.Committer.When,
		NumTotal:   len(files),
	}
	if err := u.st.CreateCommitUpdateRecord(ctx, ur); err != nil {
		return ur, err
	}

	var skippedDirs []string
	// Log a message every this many skipped directories.
	const logSkippedEvery = 40
	for _, dirFiles := range filesByDir {
		stats, err := u.updateDirectory(ctx, dirFiles)
		// Change the CommitUpdateRecord in the Store to reflect the results of the directory update.
		if err != nil {
			ur.Error = err.Error()
			if err2 := u.st.SetCommitUpdateRecord(ctx, ur); err2 != nil {
				return ur, fmt.Errorf("update failed with %w, could not set update record: %w", err, err2)
			}
			return ur, err
		}
		if stats.skipped {
			skippedDirs = append(skippedDirs, dirFiles[0].DirPath)
			if len(skippedDirs) >= logSkippedEvery {
				log.Debugf(ctx, "skipped %d directories because they have not changed since last update:\n%s",
					len(skippedDirs), strings.Join(skippedDirs, ", "))
				skippedDirs = nil
			}
		}
		ur.NumProcessed += stats.numProcessed
		ur.NumAdded += stats.numAdded
		ur.NumModified += stats.numModified
		if err := u.st.SetCommitUpdateRecord(ctx, ur); err != nil {
			return ur, err
		}
	}
	ur.EndedAt = time.Now()
	return ur, u.st.SetCommitUpdateRecord(ctx, ur)
}

// Firestore supports a maximum of 500 writes per transaction.
// See https://cloud.google.com/firestore/quotas.
const maxTransactionWrites = 500

func (u *cveUpdater) updateDirectory(ctx context.Context, dirFiles []cvelistrepo.File) (_ updateStats, err error) {
	dirPath := dirFiles[0].DirPath
	dirHash := dirFiles[0].TreeHash.String()

	// A non-empty directory hash means that we have fully processed the directory
	// with that hash. If the stored hash matches the current one, we can skip
	// this directory.
	dbHash, err := u.st.GetDirectoryHash(ctx, dirPath)
	if err != nil {
		return updateStats{}, err
	}
	if dirHash == dbHash {
		return updateStats{skipped: true}, nil
	}
	// Set the hash to something that can't match, until we fully process this directory.
	if err := u.st.SetDirectoryHash(ctx, dirPath, "in progress"); err != nil {
		return updateStats{}, err
	}
	// It's okay if we crash now; the directory hashes are just an optimization.
	// At worst we'll redo this directory next time.

	// Update files in batches.

	var stats updateStats
	for i := 0; i < len(dirFiles); i += maxTransactionWrites {
		j := i + maxTransactionWrites
		if j > len(dirFiles) {
			j = len(dirFiles)
		}
		numBatchAdds, numBatchMods, err := u.updateBatch(ctx, dirFiles[i:j])
		if err != nil {
			return updateStats{}, err
		}
		stats.numProcessed += j - i
		// Add in these two numbers here, instead of in the function passed to
		// RunTransaction, because that function may be executed multiple times.
		stats.numAdded += numBatchAdds
		stats.numModified += numBatchMods
	} // end batch loop

	// We're done with this directory, so we can remember its hash.
	if err := u.st.SetDirectoryHash(ctx, dirPath, dirHash); err != nil {
		return updateStats{}, err
	}
	return stats, nil
}

func (u *cveUpdater) updateBatch(ctx context.Context, batch []cvelistrepo.File) (numAdds, numMods int, err error) {
	startID := idFromFilename(batch[0].Filename)
	endID := idFromFilename(batch[len(batch)-1].Filename)
	defer derrors.Wrap(&err, "updateBatch(%q-%q)", startID, endID)

	err = u.st.RunTransaction(ctx, func(ctx context.Context, tx store.Transaction) error {
		numAdds = 0
		numMods = 0

		// Read information about the existing state in the store that's
		// relevant to this batch. Since the entries are sorted, we can read
		// a range of IDS.
		crs, err := tx.GetCVERecords(startID, endID)
		if err != nil {
			return err
		}
		idToRecord := map[string]*store.CVERecord{}
		for _, cr := range crs {
			idToRecord[cr.ID] = cr
		}
		// Determine what needs to be added and modified.
		var toAdd, toModify []*store.CVERecord
		for _, f := range batch {
			id := idFromFilename(f.Filename)
			old := idToRecord[id]
			if old != nil && old.BlobHash == f.BlobHash.String() {
				// No change; do nothing.
				continue
			}
			record, add, err := u.handleCVE(f, old, tx)
			if err != nil {
				return err
			}
			if add {
				toAdd = append(toAdd, record)
			} else {
				toModify = append(toModify, record)
			}
		}
		// Add/modify the records.
		for _, r := range toAdd {
			if err := tx.CreateCVERecord(r); err != nil {
				return err
			}
			numAdds++
		}
		for _, r := range toModify {
			if err := tx.SetCVERecord(r); err != nil {
				return err
			}
			numMods++
		}
		return nil
	})
	if err != nil {
		return 0, 0, err
	}
	log.Debugf(ctx, "batch updated Firestore records for %q-%q: added %d, modified %d", startID, endID, numAdds, numMods)
	return numAdds, numMods, nil
}

// checkForAliases determines if this CVE has an alias GHSA that the
// worker has already handled, and returns the appropriate triage state
// based on this.
func checkForAliases(cve *cve4.CVE, tx store.Transaction) (store.TriageState, error) {
	for _, ghsaID := range cveutils.GetAliasGHSAs(cve) {
		ghsa, err := tx.GetGHSARecord(ghsaID)
		if err != nil {
			return "", err
		}
		if ghsa != nil {
			return getTriageStateFromAlias(ghsa.TriageState), nil
		}
	}
	return store.TriageStateNeedsIssue, nil
}

// handleCVE determines how to change the store for a single CVE.
// It returns the record, and a bool indicating whether to add or modify
// the record.
func (u *cveUpdater) handleCVE(f cvelistrepo.File, old *store.CVERecord, tx store.Transaction) (record *store.CVERecord, add bool, err error) {
	defer derrors.Wrap(&err, "handleCVE(%s)", f.Filename)

	cve, err := cvelistrepo.Parse[*cve4.CVE](u.repo, f)
	if err != nil {
		return nil, false, err
	}
	var result *cveutils.TriageResult
	if cve.State == cve4.StatePublic && !u.rc.AliasHasReport(cve.ID) {
		c := cve
		// If a false positive has changed, we only care about
		// whether new reference URLs refer to a Go module.
		// We know some old ones do. So remove the old ones
		// before checking.
		if old != nil && old.TriageState == store.TriageStateFalsePositive {
			c = copyRemoving(cve, old.ReferenceURLs)
		}
		result, err = u.affectedModule(c)
		if err != nil {
			return nil, false, err
		}
	}

	pathname := path.Join(f.DirPath, f.Filename)
	// If the CVE is not in the database, add it.
	if old == nil {
		cr := store.NewCVERecord(cve, pathname, f.BlobHash.String(), u.commit)
		switch {
		case result != nil:
			triageState, err := checkForAliases(cve, tx)
			if err != nil {
				return nil, false, err
			}
			cr.TriageState = triageState
			cr.Module = result.ModulePath
			cr.Package = result.PackagePath
			cr.TriageStateReason = result.Reason
			cr.CVE = cve
		case u.rc.AliasHasReport(cve.ID):
			cr.TriageState = store.TriageStateHasVuln
		default:
			cr.TriageState = store.TriageStateNoActionNeeded
		}
		return cr, true, nil
	}
	// Change to an existing record.
	mod := *old // copy the old one
	mod.Path = pathname
	mod.BlobHash = f.BlobHash.String()
	mod.CVEState = cve.State
	mod.CommitHash = u.commit.Hash.String()
	mod.CommitTime = u.commit.Committer.When.In(time.UTC)
	switch old.TriageState {
	case store.TriageStateNoActionNeeded, store.TriageStateFalsePositive:
		if result != nil {
			// Didn't need an issue before, does now.
			mod.TriageState = store.TriageStateNeedsIssue
			mod.Module = result.ModulePath
			mod.Package = result.PackagePath
			mod.TriageStateReason = result.Reason
			mod.CVE = cve
		}
		// Else don't change the triage state, but we still want
		// to update the other changed fields.

	case store.TriageStateNeedsIssue:
		if result == nil {
			// Needed an issue, no longer does.
			mod.TriageState = store.TriageStateNoActionNeeded
			mod.Module = ""
			mod.CVE = nil
		}
		// Else don't change the triage state, but we still want
		// to update the other changed fields.

	case store.TriageStateIssueCreated, store.TriageStateUpdatedSinceIssueCreation:
		// An issue was filed, so a person should revisit this CVE.
		mod.TriageState = store.TriageStateUpdatedSinceIssueCreation
		var mp string
		if result != nil {
			mp = result.ModulePath
		}
		mod.TriageStateReason = fmt.Sprintf("CVE changed; affected module = %q", mp)
	case store.TriageStateAlias:
		// For now, do nothing.
	case store.TriageStateHasVuln:
		// There is already a Go vuln report for this CVE, so
		// nothing to do.
	default:
		return nil, false, fmt.Errorf("unknown TriageState: %q", old.TriageState)
	}
	// If the triage state changed, add the old state to the history at the beginning.
	if old.TriageState != mod.TriageState {
		mod.History = append([]*store.CVERecordSnapshot{old.Snapshot()}, mod.History...)
	}
	if mod.TriageState == store.TriageStateNeedsIssue && mod.CVE == nil {
		return nil, false, errors.New("needs issue but CVE is nil")
	}
	// If we're here, then mod is a valid modification to the DB.
	return &mod, false, nil
}

// copyRemoving returns a copy of cve with any reference that has a given URL removed.
func copyRemoving(cve *cve4.CVE, refURLs []string) *cve4.CVE {
	remove := map[string]bool{}
	for _, u := range refURLs {
		remove[u] = true
	}
	c := *cve
	var rs []cve4.Reference
	for _, r := range cve.References.Data {
		if !remove[r.URL] {
			rs = append(rs, r)
		}
	}
	c.References.Data = rs
	return &c
}

// Collect files by directory, verifying that directories are contiguous in
// the list of files. Our directory hash optimization depends on that.
func groupFilesByDirectory(files []cvelistrepo.File) ([][]cvelistrepo.File, error) {
	if len(files) == 0 {
		return nil, nil
	}
	var (
		result [][]cvelistrepo.File
		curDir []cvelistrepo.File
	)
	for _, f := range files {
		if len(curDir) > 0 && f.DirPath != curDir[0].DirPath {
			result = append(result, curDir)
			curDir = nil
		}
		curDir = append(curDir, f)
	}
	if len(curDir) > 0 {
		result = append(result, curDir)
	}
	seen := map[string]bool{}
	for _, dir := range result {
		if seen[dir[0].DirPath] {
			return nil, fmt.Errorf("directory %s is not contiguous in the sorted list of files", dir[0].DirPath)
		}
		seen[dir[0].DirPath] = true
	}
	return result, nil
}

// idFromFilename extracts the CVE ID from  a filename.
func idFromFilename(name string) string {
	return strings.TrimSuffix(path.Base(name), path.Ext(name))
}

type UpdateGHSAStats struct {
	// Number of GitHub security advisories seen.
	NumProcessed int
	// Number of GHSARecords added to the store.
	NumAdded int
	// Number of GHSARecords already in the store that were modified.
	NumModified int
}

func getTriageStateFromAlias(aliasTriageState store.TriageState) store.TriageState {
	switch aliasTriageState {
	case store.TriageStateIssueCreated,
		store.TriageStateHasVuln, store.TriageStateNeedsIssue, store.TriageStateUpdatedSinceIssueCreation:
		// The vuln was already covered by the alias ID.
		// TODO(https://go.dev/issues/55303): Add comment to
		// existing issue with new alias.
		return store.TriageStateAlias
	case store.TriageStateFalsePositive, store.TriageStateNoActionNeeded, store.TriageStateAlias:
		// Create an issue for the vuln since no issue
		// was created for the alias ID.
		return store.TriageStateNeedsIssue
	}
	return store.TriageStateNeedsIssue
}

// triageNewGHSA determines the initial triage state for the GHSA.
// It checks if we have already handled a CVE associated with this GHSA.
func triageNewGHSA(sa *ghsa.SecurityAdvisory, tx store.Transaction) (store.TriageState, error) {
	for _, alias := range sa.Identifiers {
		if alias.Type == "CVE" {
			cveID := alias.Value
			cves, err := tx.GetCVERecords(cveID, cveID)
			if err != nil {
				return store.TriageStateNeedsIssue, err
			}
			if len(cves) == 0 {
				continue
			}
			return getTriageStateFromAlias(cves[0].TriageState), nil
		}
	}
	// The GHSA has no associated CVEs.
	return store.TriageStateNeedsIssue, nil
}

func updateGHSAs(ctx context.Context, listSAs GHSAListFunc, since time.Time, st store.Store) (stats UpdateGHSAStats, err error) {
	defer derrors.Wrap(&err, "updateGHSAs(%s)", since)
	ctx, span := observe.Start(ctx, "updateGHSAs")
	defer span.End()

	defer func() {
		if err == nil {
			log.Infof(ctx, "GHSA Firestore update succeeded with since=%s: %+v", since, stats)
		}
	}()

	log.Infof(ctx, "Starting GHSA Firestore update, looking at new/modified GHSAs since=%s", since)

	// Get all of the GHSAs since the given time from GitHub.
	sas, err := listSAs(ctx, since)
	if err != nil {
		return stats, err
	}
	stats.NumProcessed = len(sas)
	if len(sas) > maxTransactionWrites {
		return stats, errors.New("number of advisories exceeds maxTransactionWrites")
	}
	numAdded := 0
	numModified := 0
	err = st.RunTransaction(ctx, func(ctx context.Context, tx store.Transaction) error {
		numAdded = 0
		numModified = 0
		// Read the existing GHSA records from the store.
		sars, err := tx.GetGHSARecords()
		if err != nil {
			return err
		}
		ghsaIDToRecord := map[string]*store.GHSARecord{}
		for _, r := range sars {
			ghsaIDToRecord[r.GHSA.ID] = r
		}

		// Determine what needs to be added and modified.
		var toAdd []*store.GHSARecord
		var toUpdate []*store.GHSARecord
		for _, sa := range sas {
			old := ghsaIDToRecord[sa.ID]
			if old == nil {
				// ghsa.List already filters for vulns in the Go ecosystem,
				// so add a record for all found GHSAs.
				triageState, err := triageNewGHSA(sa, tx)
				if err != nil {
					return err
				}
				log.Debugf(ctx, "Triage state for new %s: %s", sa.ID, triageState)
				toAdd = append(toAdd, &store.GHSARecord{
					GHSA:        sa,
					TriageState: triageState,
				})
			} else if !old.GHSA.UpdatedAt.Equal(sa.UpdatedAt) {
				// Modify record.
				mod := *old
				mod.GHSA = sa
				switch old.TriageState {
				case store.TriageStateNoActionNeeded:
					mod.TriageState = store.TriageStateNeedsIssue
					mod.TriageStateReason = "advisory was updated"
				case store.TriageStateIssueCreated:
					mod.TriageState = store.TriageStateUpdatedSinceIssueCreation
				default:
					// Don't change the TriageState.
				}
				log.Debugf(ctx, "Triage state for modified %s: %s", sa.ID, mod.TriageState)
				toUpdate = append(toUpdate, &mod)
			}
		}

		for _, r := range toAdd {
			if err := tx.CreateGHSARecord(r); err != nil {
				return err
			}
			numAdded++
		}
		for _, r := range toUpdate {
			if err := tx.SetGHSARecord(r); err != nil {
				return err
			}
			numModified++
		}

		return nil
	})
	stats.NumAdded = numAdded
	stats.NumModified = numModified
	return stats, nil
}
