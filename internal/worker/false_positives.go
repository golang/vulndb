// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"context"

	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/observe"
	"golang.org/x/vulndb/internal/worker/store"
)

// updateFalsePositives makes sure the store reflects the list of false positives.
func updateFalsePositives(ctx context.Context, st store.Store) (err error) {
	defer derrors.Wrap(&err, "updateFalsePositives")
	ctx, span := observe.Start(ctx, "updateFalsePositives")
	defer span.End()

	for i := 0; i < len(falsePositives); i += maxTransactionWrites {
		j := i + maxTransactionWrites
		if j >= len(falsePositives) {
			j = len(falsePositives)
		}
		batch := falsePositives[i:j]
		err := st.RunTransaction(ctx, func(ctx context.Context, tx store.Transaction) error {
			oldRecords, err := readCVERecords(tx, batch)
			if err != nil {
				return err
			}
			for i, cr := range batch {
				old := oldRecords[i]
				var err error
				if old == nil {
					err = tx.CreateCVERecord(cr)
				} else if old.CommitHash != cr.CommitHash && !old.CommitTime.IsZero() && old.CommitTime.Before(cr.CommitTime) {
					// If the false positive data is more recent than what is in
					// the store, then update the DB. But ignore records whose
					// commit time hasn't been populated.
					err = tx.SetCVERecord(cr)
				}
				if err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func readCVERecords(tx store.Transaction, crs []*store.CVERecord) ([]*store.CVERecord, error) {
	var olds []*store.CVERecord
	for _, cr := range crs {
		dbcrs, err := tx.GetCVERecords(cr.ID, cr.ID)
		if err != nil {
			return nil, err
		}
		var old *store.CVERecord
		if len(dbcrs) > 0 {
			old = dbcrs[0]
		}
		olds = append(olds, old)
	}
	return olds, nil
}
