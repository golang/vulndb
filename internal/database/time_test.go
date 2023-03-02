// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package database

import (
	"encoding/json"
	"testing"
)

func TestMarshalUnmarshalTime(t *testing.T) {
	var timeString = `{"time":"1999-01-01T00:00:00Z"}`
	var timeStruct = struct {
		Time Time `json:"time"`
	}{}
	if err := json.Unmarshal([]byte(timeString), &timeStruct); err != nil {
		t.Fatalf("json.Unmarshal: want success, got %v", err)
	}
	b, err := json.Marshal(timeStruct)
	if err != nil {
		t.Fatalf("json.Marshal: want success, got %v", err)
	}
	if want, got := timeString, string(b); want != got {
		t.Errorf("json.Marshal: want %s, got %s", want, got)
	}
}
