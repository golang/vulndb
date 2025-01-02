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

	"golang.org/x/vulndb/internal/idstr"
)

// MemStore is an in-memory implementation of Store, for testing.
type MemStore struct {
	mu                sync.Mutex
	cve4Records       map[string]*CVE4Record
	updateRecords     map[string]*CommitUpdateRecord
	dirHashes         map[string]string
	legacyGHSARecords map[string]*LegacyGHSARecord
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

// GetRecord implements store.GetCVE4Record.
func (ms *MemStore) GetRecord(_ context.Context, id string) (Record, error) {
	switch {
	case idstr.IsGHSA(id):
		return ms.legacyGHSARecords[id], nil
	case idstr.IsCVE(id):
		return ms.cve4Records[id], nil
	}
	return nil, fmt.Errorf("%s is not a CVE or GHSA id", id)
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

// SetRecord implements Transaction.SetCVE4Record.
func (tx *memTransaction) SetRecord(r Record) error {
	if err := r.Validate(); err != nil {
		return err
	}

	id := r.GetID()
	switch v := r.(type) {
	case *LegacyGHSARecord:
		if _, ok := tx.ms.legacyGHSARecords[id]; !ok {
			return fmt.Errorf("LegacyGHSARecord %s does not exist", id)
		}
		tx.ms.legacyGHSARecords[id] = v
	case *CVE4Record:
		if tx.ms.cve4Records[id] == nil {
			return fmt.Errorf("CVE4Record with ID %q not found", id)
		}
		tx.ms.cve4Records[id] = v
	default:
		return fmt.Errorf("unrecognized record type %T", r)
	}

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

// CreateRecord implements Transaction.CreateRecord.
func (tx *memTransaction) CreateRecord(r Record) error {
	if err := r.Validate(); err != nil {
		return err
	}

	id := r.GetID()
	switch v := r.(type) {
	case *LegacyGHSARecord:
		if _, ok := tx.ms.legacyGHSARecords[id]; ok {
			return fmt.Errorf("LegacyGHSARecord %s already exists", id)
		}
		tx.ms.legacyGHSARecords[id] = v
		return nil
	case *CVE4Record:
		if _, ok := tx.ms.cve4Records[id]; ok {
			return fmt.Errorf("CVE4Record %s already exists", id)
		}
		tx.ms.cve4Records[id] = v
		return nil
	default:
		return fmt.Errorf("unrecognized record type %T", r)
	}
}

// GetRecord implements Transaction.GetLegacyGHSARecord.
func (tx *memTransaction) GetRecord(id string) (Record, error) {
	switch {
	case idstr.IsGHSA(id):
		if r, ok := tx.ms.legacyGHSARecords[id]; ok {
			return r, nil
		}
	case idstr.IsCVE(id):
		if r, ok := tx.ms.cve4Records[id]; ok {
			return r, nil
		}
	default:
		return nil, fmt.Errorf("id %s is not a CVE or GHSA id", id)
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
