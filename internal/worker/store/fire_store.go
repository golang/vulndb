// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"cloud.google.com/go/firestore"
	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/idstr"
	"golang.org/x/vulndb/internal/report"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// FireStore is a Store implemented with Google Cloud Firestore.
//
// A Firestore DB is a set of documents. Each document has its own unique ID
// (primary key). Documents are grouped into collections, and each document can
// have sub-collections. A document can be referred to by a path of the form
// top-level-collection/doc/sub-collection/doc/...
//
// In this layout, there is a single top-level collection called Namespaces,
// with documents for each development environment. Within each namespace, there
// are some collections:
// - CVEs for CVE4Records
// - CommitUpdates for CommitUpdateRecords
// - DirHashes for directory hashes
// - GHSAs for LegacyGHSARecords.
type FireStore struct {
	namespace string
	client    *firestore.Client
	nsDoc     *firestore.DocumentRef
}

const (
	namespaceCollection  = "Namespaces"
	updateCollection     = "Updates"
	cve4Collection       = "CVEs"
	dirHashCollection    = "DirHashes"
	legacyGHSACollection = "GHSAs"
)

// NewFireStore creates a new FireStore, backed by a client to Firestore. Since
// each project can have only one Firestore database, callers must provide a
// non-empty namespace to distinguish different virtual databases (e.g. prod and
// testing).
// If non-empty, the impersonate argument should be the name of a service
// account to impersonate.
func NewFireStore(ctx context.Context, projectID, namespace, impersonate string) (_ *FireStore, err error) {
	defer derrors.Wrap(&err, "NewFireStore(%q, %q)", projectID, namespace)

	if namespace == "" {
		return nil, errors.New("empty namespace")
	}
	var opts []option.ClientOption
	if impersonate != "" {
		opts = []option.ClientOption{
			option.ImpersonateCredentials(impersonate),
			option.WithScopes("https://www.googleapis.com/auth/cloud-platform",
				"https://www.googleapis.com/auth/datastore"),
		}
	}
	client, err := firestore.NewClient(ctx, projectID, opts...)
	if err != nil {
		return nil, err
	}
	return &FireStore{
		namespace: namespace,
		client:    client,
		nsDoc:     client.Collection(namespaceCollection).Doc(namespace),
	}, nil
}

// CreateCommitUpdateRecord implements Store.CreateCommitUpdateRecord.
// On successful return, r.ID is set to the record's ID.
func (fs *FireStore) CreateCommitUpdateRecord(ctx context.Context, r *CommitUpdateRecord) (err error) {
	defer derrors.Wrap(&err, "FireStore.CreateCommitUpdateRecord")

	docref := fs.nsDoc.Collection(updateCollection).NewDoc()
	if _, err := docref.Create(ctx, r); err != nil {
		return err
	}
	r.ID = docref.ID
	return nil
}

// SetCommitUpdateRecord implements Store.SetCommitUpdateRecord.
func (fs *FireStore) SetCommitUpdateRecord(ctx context.Context, r *CommitUpdateRecord) (err error) {
	defer derrors.Wrap(&err, "FireStore.SetCommitUpdateRecord(%q)", r.ID)

	if r.ID == "" {
		return errors.New("missing ID")
	}
	_, err = fs.nsDoc.Collection(updateCollection).Doc(r.ID).Set(ctx, r)
	return err
}

// GetRecord implements store.GetRecord.
func (fs *FireStore) GetRecord(ctx context.Context, id string) (_ Record, err error) {
	defer derrors.Wrap(&err, "FireStore.GetRecord(%q)", id)

	docsnap, err := fs.recordRef(id).Get(ctx)
	if status.Code(err) == codes.NotFound {
		return nil, nil
	}

	return docsnapToRecord(docsnap)
}

// ListCommitUpdateRecords implements Store.ListCommitUpdateRecords.
func (fs *FireStore) ListCommitUpdateRecords(ctx context.Context, limit int) (_ []*CommitUpdateRecord, err error) {
	defer derrors.Wrap(&err, "Firestore.ListCommitUpdateRecords(%d)", limit)

	var urs []*CommitUpdateRecord
	q := fs.nsDoc.Collection(updateCollection).OrderBy("StartedAt", firestore.Desc)
	if limit > 0 {
		q = q.Limit(limit)
	}
	iter := q.Documents(ctx)
	defer iter.Stop()
	err = apply(iter, func(ds *firestore.DocumentSnapshot) error {
		var ur CommitUpdateRecord
		if err := ds.DataTo(&ur); err != nil {
			return err
		}
		ur.ID = ds.Ref.ID
		urs = append(urs, &ur)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return urs, nil
}

type dirHash struct {
	Hash string
}

// ListCVE4RecordsWithTriageState implements Store.ListCVE4RecordsWithTriageState.
func (fs *FireStore) ListCVE4RecordsWithTriageState(ctx context.Context, ts TriageState) (_ []*CVE4Record, err error) {
	defer derrors.Wrap(&err, "Firestore.ListCVE4RecordsWithTriageState(%s)", ts)

	q := fs.nsDoc.Collection(cve4Collection).Where("TriageState", "==", ts).OrderBy("ID", firestore.Asc)
	docsnaps, err := q.Documents(ctx).GetAll()
	if err != nil {
		return nil, err
	}
	return docsnapsToCVE4Records(docsnaps)
}

// dirHashRef returns a DocumentRef for the directory dir.
func (s *FireStore) dirHashRef(dir string) *firestore.DocumentRef {
	// Firestore IDs cannot contain slashes.
	// Do something simple and readable to fix that.
	id := strings.ReplaceAll(dir, "/", "|")
	return s.nsDoc.Collection(dirHashCollection).Doc(id)
}

// GetDirectoryHash implements Transaction.GetDirectoryHash.
func (fs *FireStore) GetDirectoryHash(ctx context.Context, dir string) (_ string, err error) {
	defer derrors.Wrap(&err, "FireStore.GetDirectoryHash(%s)", dir)

	ds, err := fs.dirHashRef(dir).Get(ctx)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return "", nil
		}
		return "", err
	}
	data, err := ds.DataAt("Hash")
	if err != nil {
		return "", err
	}
	hash, ok := data.(string)
	if !ok {
		return "", fmt.Errorf("hash data for %s is not a string", dir)
	}
	return hash, nil
}

// SetDirectoryHash implements Transaction.SetDirectoryHash.
func (fs *FireStore) SetDirectoryHash(ctx context.Context, dir, hash string) (err error) {
	defer derrors.Wrap(&err, "FireStore.SetDirectoryHash(%s, %s)", dir, hash)

	_, err = fs.dirHashRef(dir).Set(ctx, dirHash{Hash: hash})
	return err
}

// RunTransaction implements Store.RunTransaction.
func (fs *FireStore) RunTransaction(ctx context.Context, f func(context.Context, Transaction) error) (err error) {
	defer derrors.Wrap(&err, "FireStore.RunTransaction")

	return fs.client.RunTransaction(ctx,
		func(ctx context.Context, tx *firestore.Transaction) error {
			return f(ctx, &fsTransaction{fs, tx})
		})
}

func (fs *FireStore) recordRef(id string) *firestore.DocumentRef {
	var collection string
	switch {
	case idstr.IsGHSA(id):
		collection = legacyGHSACollection
	case idstr.IsCVE(id):
		collection = cve4Collection
	}
	return fs.nsDoc.Collection(collection).Doc(id)
}

// fsTransaction implements Transaction
type fsTransaction struct {
	s *FireStore
	t *firestore.Transaction
}

// SetRecord implements Transaction.SetRecord.
func (tx *fsTransaction) SetRecord(r Record) (err error) {
	defer derrors.Wrap(&err, "fsTransaction.SetRecord(%s)", r.GetID())

	if err := r.Validate(); err != nil {
		return err
	}

	return tx.t.Set(tx.s.recordRef(r.GetID()), r)
}

// GetCVE4Records implements Transaction.GetCVE4Records.
func (tx *fsTransaction) GetCVE4Records(startID, endID string) (_ []*CVE4Record, err error) {
	defer derrors.Wrap(&err, "fsTransaction.GetCVE4Records(%s, %s)", startID, endID)

	q := tx.s.nsDoc.Collection(cve4Collection).
		OrderBy(firestore.DocumentID, firestore.Asc).
		StartAt(startID).
		EndAt(endID)
	iter := tx.t.Documents(q)
	docsnaps, err := iter.GetAll()
	if err != nil {
		return nil, err
	}
	return docsnapsToCVE4Records(docsnaps)
}

func docsnapsToCVE4Records(docsnaps []*firestore.DocumentSnapshot) ([]*CVE4Record, error) {
	var crs []*CVE4Record
	for _, ds := range docsnaps {
		var cr CVE4Record
		if err := ds.DataTo(&cr); err != nil {
			return nil, err
		}
		crs = append(crs, &cr)
	}
	return crs, nil
}

type Record interface {
	GetID() string
	GetSource() report.Source
	GetUnit() string
	GetIssueReference() string
	GetIssueCreatedAt() time.Time
	GetTriageState() TriageState
	Validate() error
}

func (tx *fsTransaction) CreateRecord(r Record) (err error) {
	defer derrors.Wrap(&err, "fsTransaction.CreateRecord(%s)", r.GetID())

	if err := r.Validate(); err != nil {
		return err
	}

	return tx.t.Create(tx.s.recordRef(r.GetID()), r)
}

// GetRecord implements Transaction.GetRecord.
func (tx *fsTransaction) GetRecord(id string) (_ Record, err error) {
	defer derrors.Wrap(&err, "fsTransaction.GetRecord(%s)", id)

	docsnap, err := tx.t.Get(tx.s.recordRef(id))
	if status.Code(err) == codes.NotFound {
		return nil, nil
	}

	return docsnapToRecord(docsnap)
}

func docsnapToRecord(docsnap *firestore.DocumentSnapshot) (Record, error) {
	id := docsnap.Ref.ID

	var r Record
	switch {
	case idstr.IsGHSA(id):
		r = new(LegacyGHSARecord)
	case idstr.IsCVE(id):
		r = new(CVE4Record)
	default:
		return nil, fmt.Errorf("id %s is not a CVE or GHSA id", id)
	}

	if err := docsnap.DataTo(r); err != nil {
		return nil, err
	}

	return r, nil
}

// GetLegacyGHSARecords implements Transaction.GetLegacyGHSARecords.
func (tx *fsTransaction) GetLegacyGHSARecords() (_ []*LegacyGHSARecord, err error) {
	defer derrors.Wrap(&err, "fsTransaction.GetGHSARecords()")

	q := tx.s.nsDoc.Collection(legacyGHSACollection).
		OrderBy(firestore.DocumentID, firestore.Asc)
	iter := tx.t.Documents(q)
	docsnaps, err := iter.GetAll()
	if err != nil {
		return nil, err
	}
	return docsnapsToGHSARecords(docsnaps)
}

func docsnapsToGHSARecords(docsnaps []*firestore.DocumentSnapshot) ([]*LegacyGHSARecord, error) {
	var grs []*LegacyGHSARecord
	for _, ds := range docsnaps {
		var gr LegacyGHSARecord
		if err := ds.DataTo(&gr); err != nil {
			return nil, err
		}
		grs = append(grs, &gr)
	}
	return grs, nil
}

// Clear removes all documents in the namespace.
func (s *FireStore) Clear(ctx context.Context) (err error) {
	defer derrors.Wrap(&err, "FireStore.Clear")

	collrefs, err := s.nsDoc.Collections(ctx).GetAll()
	if err != nil {
		return err
	}
	for _, cr := range collrefs {
		if err := deleteCollection(ctx, s.client, cr, 100); err != nil {
			return err
		}
	}
	return nil
}

// Copied from https://cloud.google.com/firestore/docs/samples/firestore-data-delete-collection.
func deleteCollection(ctx context.Context, client *firestore.Client, ref *firestore.CollectionRef, batchSize int) error {
	for {
		// Get a batch of documents
		iter := ref.Limit(batchSize).Documents(ctx)
		numDeleted := 0

		// Iterate through the documents, adding a delete operation for each one
		// to a WriteBatch.
		batch := client.Batch()
		for {
			doc, err := iter.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				return err
			}
			batch.Delete(doc.Ref)
			numDeleted++
		}

		// If there are no documents to delete, the process is over.
		if numDeleted == 0 {
			return nil
		}

		if _, err := batch.Commit(ctx); err != nil {
			return err
		}
	}
}

// apply calls f for each element of iter. If f returns an error, apply stops
// immediately and returns the same error.
func apply(iter *firestore.DocumentIterator, f func(*firestore.DocumentSnapshot) error) error {
	for {
		docsnap, err := iter.Next()
		if err == iterator.Done {
			return nil
		}
		if err != nil {
			return err
		}
		if err := f(docsnap); err != nil {
			return err
		}
	}
}
