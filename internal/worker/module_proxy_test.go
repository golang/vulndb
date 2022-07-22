// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"archive/zip"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/mod/semver"
)

func TestLatestVersion(t *testing.T) {
	pt := newProxyTest()
	defer pt.Close()

	got, err := latestVersion(context.Background(), pt.URL, "golang.org/x/build")
	if err != nil {
		t.Fatal(err)
	}
	if !semver.IsValid(got) {
		t.Errorf("got invalid version %q", got)
	}
}

func TestLatestTaggedVersion(t *testing.T) {
	pt := newProxyTest()
	defer pt.Close()

	got, err := latestTaggedVersion(context.Background(), pt.URL, "golang.org/x/build")
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Errorf(`got %q, wanted ""`, got)
	}

	got, err = latestTaggedVersion(context.Background(), pt.URL, "golang.org/x/tools")
	if err != nil {
		t.Fatal(err)
	}
	if !semver.IsValid(got) {
		t.Errorf("got invalid version %q", got)
	}

}

func TestModuleZip(t *testing.T) {
	pt := newProxyTest()
	defer pt.Close()

	ctx := context.Background()
	const m = "golang.org/x/time"
	v, err := latestVersion(ctx, pt.URL, m)
	if err != nil {
		t.Fatal(err)
	}
	_, err = moduleZip(ctx, pt.URL, m, v)
	if err != nil {
		t.Fatal(err)
	}
}

type proxyTest struct {
	*httptest.Server
}

func (*proxyTest) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/golang.org/x/build/@latest":
		w.Write([]byte(`{"Version":"v0.0.0-20220722180300-9ed544e84dd1","Time":"2022-07-22T18:03:00Z"}`))
	case "/golang.org/x/build/@v/list":
	case "/golang.org/x/tools/@v/list":
		w.Write([]byte("v0.1.1\nv0.1.2\n"))
	case "/golang.org/x/time/@latest":
		w.Write([]byte(`{"Version":"v0.0.0-20220722155302-e5dcc9cfc0b9","Time":"2022-07-22T15:53:02Z"}`))
	case "/golang.org/x/time/@v/v0.0.0-20220722155302-e5dcc9cfc0b9.zip":
		zw := zip.NewWriter(w)
		fw, _ := zw.Create("golang.org/x/time@v0.0.0-20220722155302-e5dcc9cfc0b9/go.mod")
		fw.Write([]byte(`module golang.org/x/time`))
		zw.Close()
	case "/golang.org/x/mod/@v/v0.5.1.zip":
		zw := zip.NewWriter(w)
		fw, _ := zw.Create("golang.org/x/mod@v0.5.1/go.mod")
		fw.Write([]byte(`module golang.org/x/mod`))
		zw.Close()
	default:
		w.WriteHeader(404)
	}
}

func newProxyTest() *proxyTest {
	pt := &proxyTest{}
	pt.Server = httptest.NewServer(pt)
	return pt
}
