// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package osv

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestMarshalUnmarshalTime(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "no offset",
			in:   "1999-01-01T00:00:00Z",
			want: "1999-01-01T00:00:00Z",
		},
		{
			// Unmarshal should remove the offset.
			name: "offset",
			in:   "1999-01-01T01:00:00.000+01:00",
			want: "1999-01-01T00:00:00Z",
		},
	}
	for _, tc := range tests {
		in := fmt.Sprintf(`{"time":%q}`, tc.in)
		want := fmt.Sprintf(`{"time":%q}`, tc.want)
		var timeStruct = struct {
			Time Time `json:"time"`
		}{}
		if err := json.Unmarshal([]byte(in), &timeStruct); err != nil {
			t.Fatalf("json.Unmarshal = %s, want success", err)
		}
		b, err := json.Marshal(timeStruct)
		if err != nil {
			t.Fatalf("json.Marshal = %s, want success", err)
		}
		if got := string(b); want != got {
			t.Errorf("json.Marshal = %s, want %s", got, want)
		}
	}
}
