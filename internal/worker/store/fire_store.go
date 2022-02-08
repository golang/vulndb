// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package store

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"cloud.google.com/go/firestore"
	"golang.org/x/vulndb/internal/derrors"
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
// - CVEs for CVERecords
// - CommitUpdates for CommitUpdateRecords
// - DirHashes for directory hashes
// - GHSAs for GHSARecords.
type FireStore struct {
	namespace string
	client    *firestore.Client
	nsDoc     *firestore.DocumentRef
}

const (
	namespaceCollection = "Namespaces"
	updateCollection    = "Updates"
	cveCollection       = "CVEs"
	dirHashCollection   = "DirHashes"
	ghsaCollection      = "GHSAs"
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
	defer derrors.Wrap(&err, "CreateCommitUpdateRecord()")

	docref := fs.nsDoc.Collection(updateCollection).NewDoc()
	if _, err := docref.Create(ctx, r); err != nil {
		return err
	}
	r.ID = docref.ID
	return nil
}

// SetCommitUpdateRecord implements Store.SetCommitUpdateRecord.
func (fs *FireStore) SetCommitUpdateRecord(ctx context.Context, r *CommitUpdateRecord) (err error) {
	defer derrors.Wrap(&err, "SetCommitUpdateRecord(%q)", r.ID)

	if r.ID == "" {
		return errors.New("missing ID")
	}
	_, err = fs.nsDoc.Collection(updateCollection).Doc(r.ID).Set(ctx, r)
	return err
}

// GetCVERecord implements store.GetCVERecord.
func (fs *FireStore) GetCVERecord(ctx context.Context, id string) (_ *CVERecord, err error) {
	defer derrors.Wrap(&err, "GetCVERecord(%q)", id)

	docsnap, err := fs.cveRecordRef(id).Get(ctx)
	if status.Code(err) == codes.NotFound {
		return nil, nil
	}
	var cr CVERecord
	if err := docsnap.DataTo(&cr); err != nil {
		return nil, err
	}
	return &cr, nil
}

// ListCommitUpdateRecords implements Store.ListCommitUpdateRecords.
func (fs *FireStore) ListCommitUpdateRecords(ctx context.Context, limit int) ([]*CommitUpdateRecord, error) {
	var urs []*CommitUpdateRecord
	q := fs.nsDoc.Collection(updateCollection).OrderBy("StartedAt", firestore.Desc)
	if limit > 0 {
		q = q.Limit(limit)
	}
	iter := q.Documents(ctx)
	for {
		docsnap, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		var ur CommitUpdateRecord
		if err := docsnap.DataTo(&ur); err != nil {
			return nil, err
		}
		ur.ID = docsnap.Ref.ID
		urs = append(urs, &ur)
	}
	return urs, nil
}

type dirHash struct {
	Hash string
}

// ListCVERecordsWithTriageState implements Store.ListCVERecordsWithTriageState.
func (fs *FireStore) ListCVERecordsWithTriageState(ctx context.Context, ts TriageState) (_ []*CVERecord, err error) {
	defer derrors.Wrap(&err, "ListCVERecordsWithTriageState(%s)", ts)

	q := fs.nsDoc.Collection(cveCollection).Where("TriageState", "==", ts).OrderBy("ID", firestore.Asc)
	docsnaps, err := q.Documents(ctx).GetAll()
	if err != nil {
		return nil, err
	}
	return docsnapsToCVERecords(docsnaps)
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
	defer derrors.Wrap(&err, "GetDirectoryHash(%s)", dir)

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
func (fs *FireStore) SetDirectoryHash(ctx context.Context, dir, hash string) error {
	_, err := fs.dirHashRef(dir).Set(ctx, dirHash{Hash: hash})
	return err
}

// RunTransaction implements Store.RunTransaction.
func (fs *FireStore) RunTransaction(ctx context.Context, f func(context.Context, Transaction) error) error {
	return fs.client.RunTransaction(ctx,
		func(ctx context.Context, tx *firestore.Transaction) error {
			return f(ctx, &fsTransaction{fs, tx})
		})
}

// cveRecordRef returns a DocumentRef to the CVERecord with id.
func (fs *FireStore) cveRecordRef(id string) *firestore.DocumentRef {
	return fs.nsDoc.Collection(cveCollection).Doc(id)
}

// ghsaRecordRef returns a DocumentRef to the GHSARecord with id.
func (fs *FireStore) ghsaRecordRef(id string) *firestore.DocumentRef {
	return fs.nsDoc.Collection(ghsaCollection).Doc(id)
}

// fsTransaction implements Transaction
type fsTransaction struct {
	s *FireStore
	t *firestore.Transaction
}

// CreateCVERecord implements Transaction.CreateCVERecord.
func (tx *fsTransaction) CreateCVERecord(r *CVERecord) (err error) {
	defer derrors.Wrap(&err, "FireStore.CreateCVERecord(%s)", r.ID)

	if err := r.Validate(); err != nil {
		return err
	}
	return tx.t.Create(tx.s.cveRecordRef(r.ID), r)
}

// SetCVERecord implements Transaction.SetCVERecord.
func (tx *fsTransaction) SetCVERecord(r *CVERecord) (err error) {
	defer derrors.Wrap(&err, "SetCVERecord(%s)", r.ID)

	if err := r.Validate(); err != nil {
		return err
	}
	return tx.t.Set(tx.s.cveRecordRef(r.ID), r)
}

// GetCVERecords implements Transaction.GetCVERecords.
func (tx *fsTransaction) GetCVERecords(startID, endID string) (_ []*CVERecord, err error) {
	defer derrors.Wrap(&err, "GetCVERecords(%s, %s)", startID, endID)

	q := tx.s.nsDoc.Collection(cveCollection).
		OrderBy(firestore.DocumentID, firestore.Asc).
		StartAt(startID).
		EndAt(endID)
	iter := tx.t.Documents(q)
	docsnaps, err := iter.GetAll()
	if err != nil {
		return nil, err
	}
	return docsnapsToCVERecords(docsnaps)
}

func docsnapsToCVERecords(docsnaps []*firestore.DocumentSnapshot) ([]*CVERecord, error) {
	var crs []*CVERecord
	for _, ds := range docsnaps {
		var cr CVERecord
		if err := ds.DataTo(&cr); err != nil {
			return nil, err
		}
		crs = append(crs, &cr)
	}
	return crs, nil
}

// CreateGHSARecord implements Transaction.CreateGHSARecord.
func (tx *fsTransaction) CreateGHSARecord(r *GHSARecord) (err error) {
	defer derrors.Wrap(&err, "FireStore.CreateGHSARecord(%s)", r.GHSA.ID)

	return tx.t.Create(tx.s.ghsaRecordRef(r.GHSA.ID), r)
}

// SetGHSARecord implements Transaction.SetGHSARecord.
func (tx *fsTransaction) SetGHSARecord(r *GHSARecord) (err error) {
	defer derrors.Wrap(&err, "SetGHSARecord(%s)", r.GHSA.ID)

	return tx.t.Set(tx.s.ghsaRecordRef(r.GHSA.ID), r)
}

// GetGHSARecord implements Transaction.GetGHSARecord.
func (tx *fsTransaction) GetGHSARecord(id string) (_ *GHSARecord, err error) {
	defer derrors.Wrap(&err, "GetGHSARecord(%s)", id)

	docsnap, err := tx.t.Get(tx.s.ghsaRecordRef(id))
	if status.Code(err) == codes.NotFound {
		return nil, nil
	}
	var gr GHSARecord
	if err := docsnap.DataTo(&gr); err != nil {
		return nil, err
	}
	return &gr, nil
}

// GetGHSARecords implements Transaction.GetGHSARecords.
func (tx *fsTransaction) GetGHSARecords() (_ []*GHSARecord, err error) {
	defer derrors.Wrap(&err, "GetGHSARecords()")

	q := tx.s.nsDoc.Collection(ghsaCollection).
		OrderBy(firestore.DocumentID, firestore.Asc)
	iter := tx.t.Documents(q)
	docsnaps, err := iter.GetAll()
	if err != nil {
		return nil, err
	}
	return docsnapsToGHSARecords(docsnaps)
}

func docsnapsToGHSARecords(docsnaps []*firestore.DocumentSnapshot) ([]*GHSARecord, error) {
	var grs []*GHSARecord
	for _, ds := range docsnaps {
		var gr GHSARecord
		if err := ds.DataTo(&gr); err != nil {
			return nil, err
		}
		grs = append(grs, &gr)
	}
	return grs, nil
}

// Clear removes all documents in the namespace.
func (s *FireStore) Clear(ctx context.Context) (err error) {
	defer derrors.Wrap(&err, "Clear")

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
