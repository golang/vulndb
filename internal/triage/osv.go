// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package triage

import (
	"fmt"

	"golang.org/x/vulndb/internal/genericosv"
)

func ContainsGoModule(osv *genericosv.Entry) *Result {
	for _, a := range osv.Affected {
		if a.Package.Ecosystem == genericosv.EcosystemGo {
			return &Result{
				ModulePath: a.Package.Name,
				Reason:     fmt.Sprintf("%q is marked as Go ecosystem", a.Package.Name),
			}
		}
	}
	return nil
}
