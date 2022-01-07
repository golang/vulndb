// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"context"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"golang.org/x/vulndb/internal/cvelistrepo"
	"golang.org/x/vulndb/internal/cveschema"
	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/worker/log"
	"golang.org/x/vulndb/internal/worker/store"
)

// A triageFunc triages a CVE: it decides whether an issue needs to be filed.
// If so, it returns a non-empty string indicating the possibly
// affected module.
type triageFunc func(*cveschema.CVE) (*triageResult, error)

// An updater performs an update operation on the DB.
type updater struct {
	repo           *git.Repository
	commit         *object.Commit
	st             store.Store
	knownIDs       map[string]bool
	affectedModule triageFunc
}

type updateStats struct {
	numProcessed, numAdded, numModified int
}

// newUpdater creates an updater for updating the store with information from
// the repo commit.
// needsIssue determines whether a CVE needs an issue to be filed for it.
func newUpdater(repo *git.Repository, commit *object.Commit, st store.Store, knownVulnIDs []string, needsIssue triageFunc) *updater {
	u := &updater{
		repo:           repo,
		commit:         commit,
		st:             st,
		knownIDs:       map[string]bool{},
		affectedModule: needsIssue,
	}
	for _, k := range knownVulnIDs {
		u.knownIDs[k] = true
	}
	return u
}

// update updates the DB to match the repo at the given commit.
// It also triages new or changed issues.
func (u *updater) update(ctx context.Context) (ur *store.CommitUpdateRecord, err error) {
	// We want the action of reading the old DB record, updating it and
	// writing it back to be atomic. It would be too expensive to do that one
	// record at a time. Ideally we'd process the whole repo commit in one
	// transaction, but Firestore has a limit on how many writes one
	// transaction can do, so the CVE files in the repo are processed in
	// batches, one transaction per batch.
	defer derrors.Wrap(&err, "updater.update(%s)", u.commit.Hash)

	defer func() {
		if err != nil {
			log.Errorf(ctx, "update failed: %v", err)
		} else {
			var nAdded, nModified int64
			if ur != nil {
				nAdded = int64(ur.NumAdded)
				nModified = int64(ur.NumModified)
			}
			log.Infof(ctx, "update succeeded on %s: added %d, modified %d",
				u.commit.Hash, nAdded, nModified)
		}
	}()

	log.Infof(ctx, "update starting on %s", u.commit.Hash)

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

	for _, dirFiles := range filesByDir {
		stats, err := u.updateDirectory(ctx, dirFiles)
		// Change the CommitUpdateRecord in the Store to reflect the results of the directory update.
		if err != nil {
			ur.Error = err.Error()
			if err2 := u.st.SetCommitUpdateRecord(ctx, ur); err2 != nil {
				return ur, fmt.Errorf("update failed with %w, could not set update record: %v", err, err2)
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

func (u *updater) updateDirectory(ctx context.Context, dirFiles []cvelistrepo.File) (_ updateStats, err error) {
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
		log.Infof(ctx, "skipping directory %s because the hashes match", dirPath)
		return updateStats{}, nil
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

func (u *updater) updateBatch(ctx context.Context, batch []cvelistrepo.File) (numAdds, numMods int, err error) {
	startID := idFromFilename(batch[0].Filename)
	endID := idFromFilename(batch[len(batch)-1].Filename)
	defer derrors.Wrap(&err, "updateBatch(%s-%s)", startID, endID)

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
		for _, f := range batch {
			id := idFromFilename(f.Filename)
			old := idToRecord[id]
			if old != nil && old.BlobHash == f.BlobHash.String() {
				// No change; do nothing.
				continue
			}
			added, err := u.handleCVE(f, old, tx)
			if err != nil {
				return err
			}
			if added {
				numAdds++
			} else {
				numMods++
			}
		}
		return nil
	})
	if err != nil {
		return 0, 0, err
	}
	log.Debugf(ctx, "update transaction %s=%s: added %d, modified %d", startID, endID, numAdds, numMods)
	return numAdds, numMods, nil
}

// handleCVE determines how to change the store for a single CVE.
// The CVE will definitely be either added, if it's new, or modified, if it's
// already in the DB.
func (u *updater) handleCVE(f cvelistrepo.File, old *store.CVERecord, tx store.Transaction) (added bool, err error) {
	defer derrors.Wrap(&err, "handleCVE(%s)", f.Filename)
	cve, err := cvelistrepo.ParseCVE(u.repo, f)
	if err != nil {
		return false, err
	}
	var result *triageResult
	if cve.State == cveschema.StatePublic && !u.knownIDs[cve.ID] {
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
			return false, err
		}
	}

	pathname := path.Join(f.DirPath, f.Filename)
	// If the CVE is not in the database, add it.
	if old == nil {
		cr := store.NewCVERecord(cve, pathname, f.BlobHash.String(), u.commit)
		switch {
		case result != nil:
			cr.TriageState = store.TriageStateNeedsIssue
			cr.Module = result.modulePath
			cr.Package = result.packagePath
			cr.TriageStateReason = result.reason
			cr.CVE = cve
		case u.knownIDs[cve.ID]:
			cr.TriageState = store.TriageStateHasVuln
		default:
			cr.TriageState = store.TriageStateNoActionNeeded
		}
		if err := tx.CreateCVERecord(cr); err != nil {
			return false, err
		}
		return true, nil
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
			mod.Module = result.modulePath
			mod.Package = result.packagePath
			mod.TriageStateReason = result.reason
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
			mp = result.modulePath
		}
		mod.TriageStateReason = fmt.Sprintf("CVE changed; affected module = %q", mp)
	case store.TriageStateHasVuln:
		// There is already a Go vuln report for this CVE, so
		// nothing to do.
	default:
		return false, fmt.Errorf("unknown TriageState: %q", old.TriageState)
	}
	// If the triage state changed, add the old state to the history at the beginning.
	if old.TriageState != mod.TriageState {
		mod.History = append([]*store.CVERecordSnapshot{old.Snapshot()}, mod.History...)
	}
	// If we're here, then mod is a modification to the DB.
	if err := tx.SetCVERecord(&mod); err != nil {
		return false, err
	}
	return false, nil
}

// copyRemoving returns a copy of cve with any reference that has a given URL removed.
func copyRemoving(cve *cveschema.CVE, refURLs []string) *cveschema.CVE {
	remove := map[string]bool{}
	for _, u := range refURLs {
		remove[u] = true
	}
	c := *cve
	var rs []cveschema.Reference
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
