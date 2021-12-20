// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"context"

	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/worker/store"
)

func InsertFalsePositives(ctx context.Context, st store.Store) (err error) {
	defer derrors.Wrap(&err, "InsertFalsePositives")

	for i := 0; i < len(falsePositives); i += maxTransactionWrites {
		j := i + maxTransactionWrites
		if j >= len(falsePositives) {
			j = len(falsePositives)
		}
		err := st.RunTransaction(ctx, func(ctx context.Context, tx store.Transaction) error {
			for _, cr := range falsePositives[i:j] {
				if err := tx.CreateCVERecord(cr); err != nil {
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

// falsePositivesInserted reports whether the list of false positives has been
// added to the store.
func falsePositivesInserted(ctx context.Context, st store.Store) (bool, error) {
	// Check the first and last IDs. See gen_false_positives.go for the list.
	ids := []string{"CVE-2013-2124", "CVE-2021-3391"}
	for _, id := range ids {
		cr, err := st.GetCVERecord(ctx, id)
		if err != nil {
			return false, err
		}
		if cr == nil {
			return false, nil
		}
	}
	return true, nil
}
