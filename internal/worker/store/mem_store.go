// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package store

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sort"
	"sync"
	"time"
)

// MemStore is an in-memory implementation of Store, for testing.
type MemStore struct {
	mu                sync.Mutex
	cve4Records       map[string]*CVE4Record
	updateRecords     map[string]*CommitUpdateRecord
	dirHashes         map[string]string
	legacyGHSARecords map[string]*LegacyGHSARecord
	modScanRecords    []*ModuleScanRecord
}

// NewMemStore creates a new, empty MemStore.
func NewMemStore() *MemStore {
	m := &MemStore{}
	_ = m.Clear(context.Background())
	return m
}

// Clear removes all data from the MemStore.
func (ms *MemStore) Clear(context.Context) error {
	ms.cve4Records = map[string]*CVE4Record{}
	ms.updateRecords = map[string]*CommitUpdateRecord{}
	ms.dirHashes = map[string]string{}
	ms.legacyGHSARecords = map[string]*LegacyGHSARecord{}
	ms.modScanRecords = nil
	return nil
}

// CVE4Records return all the CVE4Records of the store.
func (ms *MemStore) CVE4Records() map[string]*CVE4Record {
	return ms.cve4Records
}

// CreateCommitUpdateRecord implements Store.CreateCommitUpdateRecord.
func (ms *MemStore) CreateCommitUpdateRecord(ctx context.Context, r *CommitUpdateRecord) error {
	r.ID = fmt.Sprint(rand.Uint32())
	if ms.updateRecords[r.ID] != nil {
		panic("duplicate ID")
	}
	r.UpdatedAt = time.Now()
	return ms.SetCommitUpdateRecord(ctx, r)
}

// SetCommitUpdateRecord implements Store.SetCommitUpdateRecord.
func (ms *MemStore) SetCommitUpdateRecord(_ context.Context, r *CommitUpdateRecord) error {
	if r.ID == "" {
		return errors.New("SetCommitUpdateRecord: need ID")
	}
	c := *r
	c.UpdatedAt = time.Now()
	ms.updateRecords[c.ID] = &c
	return nil
}

// ListCommitUpdateRecords implements Store.ListCommitUpdateRecords.
func (ms *MemStore) ListCommitUpdateRecords(_ context.Context, limit int) ([]*CommitUpdateRecord, error) {
	var urs []*CommitUpdateRecord
	for _, ur := range ms.updateRecords {
		urs = append(urs, ur)
	}
	sort.Slice(urs, func(i, j int) bool {
		return urs[i].StartedAt.After(urs[j].StartedAt)
	})
	if limit > 0 && len(urs) > limit {
		urs = urs[:limit]
	}
	return urs, nil
}

// GetCVE4Record implements store.GetCVE4Record.
func (ms *MemStore) GetCVE4Record(ctx context.Context, id string) (*CVE4Record, error) {
	return ms.cve4Records[id], nil
}

// ListCVE4RecordsWithTriageState implements Store.ListCVE4RecordsWithTriageState.
func (ms *MemStore) ListCVE4RecordsWithTriageState(_ context.Context, ts TriageState) ([]*CVE4Record, error) {
	var crs []*CVE4Record
	for _, r := range ms.cve4Records {
		if r.TriageState == ts {
			crs = append(crs, r)
		}
	}
	sort.Slice(crs, func(i, j int) bool {
		return crs[i].ID < crs[j].ID
	})
	return crs, nil
}

// CreateModuleScanRecord implements Store.CreateModuleScanRecord.
func (ms *MemStore) CreateModuleScanRecord(_ context.Context, r *ModuleScanRecord) error {
	if err := r.Validate(); err != nil {
		return err
	}
	ms.modScanRecords = append(ms.modScanRecords, r)
	return nil
}

// GetModuleScanRecord implements store.GetModuleScanRecord.
func (ms *MemStore) GetModuleScanRecord(_ context.Context, path, version string, dbTime time.Time) (*ModuleScanRecord, error) {
	var m *ModuleScanRecord
	for _, r := range ms.modScanRecords {
		if r.Path == path && r.Version == version && r.DBTime.Equal(dbTime) {
			if m == nil || m.FinishedAt.Before(r.FinishedAt) {
				m = r
			}
		}
	}
	return m, nil
}

// ListModuleScanRecords implements Store.ListModuleScanRecords.
func (ms *MemStore) ListModuleScanRecords(ctx context.Context, limit int) ([]*ModuleScanRecord, error) {
	rs := make([]*ModuleScanRecord, len(ms.modScanRecords))
	copy(rs, ms.modScanRecords)
	sort.Slice(rs, func(i, j int) bool { return rs[i].FinishedAt.After(rs[j].FinishedAt) })
	if limit == 0 || limit >= len(rs) {
		return rs, nil
	}
	return rs[:limit], nil
}

// GetDirectoryHash implements Transaction.GetDirectoryHash.
func (ms *MemStore) GetDirectoryHash(_ context.Context, dir string) (string, error) {
	return ms.dirHashes[dir], nil
}

// SetDirectoryHash implements Transaction.SetDirectoryHash.
func (ms *MemStore) SetDirectoryHash(_ context.Context, dir, hash string) error {
	ms.dirHashes[dir] = hash
	return nil
}

// RunTransaction implements Store.RunTransaction.
// A transaction runs with a single lock on the entire DB.
func (ms *MemStore) RunTransaction(ctx context.Context, f func(context.Context, Transaction) error) error {
	tx := &memTransaction{ms}
	ms.mu.Lock()
	defer ms.mu.Unlock()
	return f(ctx, tx)
}

// memTransaction implements Store.Transaction.
type memTransaction struct {
	ms *MemStore
}

// CreateCVE4Record implements Transaction.CreateCVE4Record.
func (tx *memTransaction) CreateCVE4Record(r *CVE4Record) error {
	if err := r.Validate(); err != nil {
		return err
	}
	tx.ms.cve4Records[r.ID] = r
	return nil
}

// SetCVE4Record implements Transaction.SetCVE4Record.
func (tx *memTransaction) SetCVE4Record(r *CVE4Record) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if tx.ms.cve4Records[r.ID] == nil {
		return fmt.Errorf("CVE4Record with ID %q not found", r.ID)
	}
	tx.ms.cve4Records[r.ID] = r
	return nil
}

// GetCVE4Records implements Transaction.GetCVE4Records.
func (tx *memTransaction) GetCVE4Records(startID, endID string) ([]*CVE4Record, error) {
	var crs []*CVE4Record
	for id, r := range tx.ms.cve4Records {
		if id >= startID && id <= endID {
			c := *r
			crs = append(crs, &c)
		}
	}
	// Sort for testing.
	sort.Slice(crs, func(i, j int) bool {
		return crs[i].ID < crs[j].ID
	})
	return crs, nil
}

// CreateLegacyGHSARecord implements Transaction.CreateLegacyGHSARecord.
func (tx *memTransaction) CreateLegacyGHSARecord(r *LegacyGHSARecord) error {
	if _, ok := tx.ms.legacyGHSARecords[r.GHSA.ID]; ok {
		return fmt.Errorf("LegacyGHSARecord %s already exists", r.GHSA.ID)
	}
	tx.ms.legacyGHSARecords[r.GHSA.ID] = r
	return nil
}

// SetLegacyGHSARecord implements Transaction.SetLegacyGHSARecord.
func (tx *memTransaction) SetLegacyGHSARecord(r *LegacyGHSARecord) error {
	if _, ok := tx.ms.legacyGHSARecords[r.GHSA.ID]; !ok {
		return fmt.Errorf("LegacyGHSARecord %s does not exist", r.GHSA.ID)
	}
	tx.ms.legacyGHSARecords[r.GHSA.ID] = r
	return nil
}

// GetLegacyGHSARecord implements Transaction.GetLegacyGHSARecord.
func (tx *memTransaction) GetLegacyGHSARecord(id string) (*LegacyGHSARecord, error) {
	if r, ok := tx.ms.legacyGHSARecords[id]; ok {
		return r, nil
	}
	return nil, nil
}

// GetLegacyGHSARecords implements Transaction.GetLegacyGHSARecords.
func (tx *memTransaction) GetLegacyGHSARecords() ([]*LegacyGHSARecord, error) {
	var recs []*LegacyGHSARecord
	for _, r := range tx.ms.legacyGHSARecords {
		recs = append(recs, r)
	}
	return recs, nil
}
