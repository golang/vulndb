// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package database

import (
	"encoding/json"
	"testing"

	"golang.org/x/tools/txtar"
)

func TestMarshalUnmarshal(t *testing.T) {
	ar, err := txtar.ParseFile(validTxtar)
	if err != nil {
		t.Fatal(err)
	}

	testMarshalUnmarshal := func(t *testing.T, filename string, v any) {
		data, err := data(ar, filename)
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(data, &v); err != nil {
			t.Fatal(err)
		}
		marshaled, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := string(marshaled), string(data); got != want {
			t.Errorf("json.Marshal: got \n%s\n, want \n%s", got, want)
		}
	}

	t.Run("DBIndex", func(t *testing.T) {
		var db DBMeta
		testMarshalUnmarshal(t, "index/db.json", &db)
	})

	t.Run("ModulesIndex", func(t *testing.T) {
		modules := make(ModulesIndex)
		testMarshalUnmarshal(t, "index/modules.json", &modules)
	})

	t.Run("VulnsIndex", func(t *testing.T) {
		vulns := make(VulnsIndex)
		testMarshalUnmarshal(t, "index/vulns.json", &vulns)
	})
}
