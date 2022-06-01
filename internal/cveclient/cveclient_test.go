// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cveclient

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/vulndb/internal/cveschema"
)

var (
	testApiKey  = "test_api_key"
	testApiOrg  = "test_api_org"
	testApiUser = "test_api_user"
)

var defaultTestCVE = newTestCVE("CVE-2022-0000", cveschema.StateReserved, "2022")
var defaultTestCVEs = AssignedCVEList{
	defaultTestCVE, newTestCVE("CVE-2022-0001", cveschema.StateReserved, "2022"),
}
var defaultTestQuota = Quota{
	Quota:     10,
	Reserved:  3,
	Available: 7,
}

var (
	testTime2022 = time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC)
	testTime2000 = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	testTime1999 = time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC)
	testTime1992 = time.Date(1992, 1, 1, 0, 0, 0, 0, time.UTC)
)

func newTestCVE(id, state, year string) AssignedCVE {
	return AssignedCVE{
		ID:       id,
		Year:     year,
		State:    state,
		CNA:      testApiOrg,
		Reserved: testTime2022,
		RequestedBy: RequestedBy{
			CNA:  testApiOrg,
			User: testApiUser,
		},
	}
}

func newTestClientAndServer(handler http.HandlerFunc) (*Client, *httptest.Server) {
	s := httptest.NewServer(http.HandlerFunc(handler))
	c := New(Config{
		Endpoint: s.URL,
		Key:      testApiKey,
		Org:      testApiOrg,
		User:     testApiUser})
	c.c = s.Client()
	return c, s
}

func checkHeaders(t *testing.T, r *http.Request) {
	if got, want := r.Header.Get(headerApiUser), testApiUser; got != want {
		t.Errorf("HTTP Header %q = %s, want %s", headerApiUser, got, want)
	}
	if got, want := r.Header.Get(headerApiOrg), testApiOrg; got != want {
		t.Errorf("HTTP Header %q = %s, want %s", headerApiOrg, got, want)
	}
	if got, want := r.Header.Get(headerApiKey), testApiKey; got != want {
		t.Errorf("HTTP Header %q = %s, want %s", headerApiKey, got, want)
	}
}

func newTestHandler(t *testing.T, mockStatus int, mockResponse any, validateRequest func(t *testing.T, r *http.Request)) http.HandlerFunc {
	mr, err := json.Marshal(mockResponse)
	if err != nil {
		t.Fatalf("could not marshal mock response: %v", err)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if validateRequest != nil {
			validateRequest(t, r)
		}
		checkHeaders(t, r)
		w.WriteHeader(mockStatus)
		w.Write(mr)
	}
}

func newTestHandlerMultiPage(t *testing.T, mockResponses []any, validateRequest func(t *testing.T, r *http.Request)) http.HandlerFunc {
	var mrs [][]byte
	for _, r := range mockResponses {
		mr, err := json.Marshal(r)
		if err != nil {
			t.Fatalf("could not marshal mock response: %v", err)
		}
		mrs = append(mrs, mr)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if validateRequest != nil {
			validateRequest(t, r)
		}
		parsed, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			t.Fatalf("could not parse URL query: %v", err)
		}
		var page int
		if pages := parsed["page"]; len(pages) >= 1 {
			page, err = strconv.Atoi(parsed["page"][0])
			if err != nil {
				t.Fatalf("could not parse page as int: %v", err)
			}
		}
		checkHeaders(t, r)
		w.WriteHeader(http.StatusOK)
		w.Write(mrs[page])
	}
}

func TestCreateReserveIDsRequest(t *testing.T) {
	tests := []struct {
		opts       ReserveOptions
		wantParams string
	}{
		{
			opts: ReserveOptions{
				NumIDs: 1,
				Year:   2000,
				Mode:   SequentialRequest,
			},
			wantParams: "amount=1&cve_year=2000&short_name=test_api_org",
		},
		{
			opts: ReserveOptions{
				NumIDs: 2,
				Year:   2022,
				Mode:   SequentialRequest,
			},
			wantParams: "amount=2&batch_type=sequential&cve_year=2022&short_name=test_api_org",
		},
		{
			opts: ReserveOptions{
				NumIDs: 3,
				Year:   2010,
				Mode:   NonsequentialRequest,
			},
			wantParams: "amount=3&batch_type=nonsequential&cve_year=2010&short_name=test_api_org",
		},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("NumIDs=%d/Year=%d/Mode=%s", test.opts.NumIDs, test.opts.Year, test.opts.Mode), func(t *testing.T) {
			c, s := newTestClientAndServer(nil)
			defer s.Close()
			req, err := c.createReserveIDsRequest(test.opts)
			if err != nil {
				t.Fatalf("unexpected error getting reserve ID request: %v", err)
			}
			if got, want := req.URL.RawQuery, test.wantParams; got != want {
				t.Errorf("incorrect request params: got %v, want %v", got, want)
			}
		})
	}
}

type queryFunc func(c *Client) (any, error)

var (
	reserveIDsQuery = func(c *Client) (any, error) {
		return c.ReserveIDs(ReserveOptions{
			NumIDs: 2,
			Year:   2002,
			Mode:   SequentialRequest,
		})
	}
	retrieveQuotaQuery = func(c *Client) (any, error) {
		return c.RetrieveQuota()
	}
	retrieveCVEQuery = func(c *Client) (any, error) {
		return c.RetrieveCVE(defaultTestCVE.ID)
	}
	listOrgCVEsQuery = func(c *Client) (any, error) {
		return c.ListOrgCVEs(&ListOptions{})
	}
)

func TestAllSuccess(t *testing.T) {
	tests := []struct {
		name           string
		mockStatus     int
		mockResponse   any
		query          queryFunc
		wantHTTPMethod string
		wantPath       string
		want           any
	}{
		{
			name:       "ReserveIDs",
			query:      reserveIDsQuery,
			mockStatus: http.StatusOK,
			mockResponse: reserveIDsResponse{
				CVEs: defaultTestCVEs},
			wantHTTPMethod: http.MethodPost,
			wantPath:       "/api/cve-id",
			want:           defaultTestCVEs,
		},
		{
			name:       "ReserveIDs/partial content ok",
			query:      reserveIDsQuery,
			mockStatus: http.StatusPartialContent,
			mockResponse: reserveIDsResponse{
				CVEs: AssignedCVEList{defaultTestCVE}},
			wantHTTPMethod: http.MethodPost,
			wantPath:       "/api/cve-id",
			want:           AssignedCVEList{defaultTestCVE},
		},
		{
			name:           "RetrieveQuota",
			query:          retrieveQuotaQuery,
			mockStatus:     http.StatusOK,
			mockResponse:   defaultTestQuota,
			wantHTTPMethod: http.MethodGet,
			wantPath:       "/api/org/test_api_org/id_quota",
			want:           defaultTestQuota,
		},
		{
			name:           "RetrieveCVE",
			query:          retrieveCVEQuery,
			mockStatus:     http.StatusOK,
			mockResponse:   defaultTestCVE,
			wantHTTPMethod: http.MethodGet,
			wantPath:       "/api/cve-id/CVE-2022-0000",
			want:           defaultTestCVE,
		},
		{
			name:       "ListOrgCVEs/single page",
			query:      listOrgCVEsQuery,
			mockStatus: http.StatusOK,
			mockResponse: listOrgCVEsResponse{
				CurrentPage: 0,
				NextPage:    -1,
				CVEs:        defaultTestCVEs,
			},
			wantHTTPMethod: http.MethodGet,
			wantPath:       "/api/cve-id",
			want:           defaultTestCVEs,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			validateRequest := func(t *testing.T, r *http.Request) {
				if got, want := r.Method, test.wantHTTPMethod; got != want {
					t.Errorf("incorrect HTTP method: got %v, want %v", got, want)
				}
				if got, want := r.URL.Path, test.wantPath; got != want {
					t.Errorf("incorrect request URL path: got %v, want %v", got, want)
				}
			}
			c, s := newTestClientAndServer(
				newTestHandler(t, test.mockStatus, test.mockResponse, validateRequest))
			defer s.Close()
			got, err := test.query(c)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if want := test.want; !reflect.DeepEqual(got, want) {
				t.Errorf("got %v, want %v", got, want)
			}
		})
	}
}

func TestAllFail(t *testing.T) {
	tests := []struct {
		name  string
		query queryFunc
	}{
		{
			name:  "ReserveIDs",
			query: reserveIDsQuery,
		},
		{
			name:  "RetrieveQuota",
			query: retrieveQuotaQuery,
		},
		{
			name:  "RetrieveCVE",
			query: retrieveCVEQuery,
		},
		{
			name:  "ListOrgCVEs",
			query: listOrgCVEsQuery,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockStatus := http.StatusUnauthorized
			mockResponse := apiError{
				Error:   "more info",
				Message: "even more info",
			}
			c, s := newTestClientAndServer(newTestHandler(t, mockStatus, mockResponse, nil))
			defer s.Close()
			want := "401 Unauthorized: more info: even more info"
			_, err := test.query(c)
			if err == nil {
				t.Fatalf("unexpected success: want err %v", want)
			}
			if got := err.Error(); !strings.Contains(got, want) {
				t.Errorf("unexpected error string: got %v, want %v", got, want)
			}
		})
	}
}

func TestCreateListOrgCVEsRequest(t *testing.T) {
	tests := []struct {
		opts       ListOptions
		page       int
		wantParams string
	}{
		{
			opts: ListOptions{
				State:          cveschema.StateReserved,
				Year:           2000,
				ReservedBefore: &testTime2022,
				ReservedAfter:  &testTime1999,
				ModifiedBefore: &testTime2000,
				ModifiedAfter:  &testTime1992,
			},
			page:       0,
			wantParams: "cve_id_year=2000&state=RESERVED&time_modified.gt=1992-01-01T00%3A00%3A00Z&time_modified.lt=2000-01-01T00%3A00%3A00Z&time_reserved.gt=1999-01-01T00%3A00%3A00Z&time_reserved.lt=2022-01-01T00%3A00%3A00Z",
		},
		{
			opts: ListOptions{
				State:          cveschema.StateRejected,
				Year:           1999,
				ReservedBefore: &testTime1999,
				ReservedAfter:  &testTime2000,
				ModifiedBefore: &testTime1992,
				ModifiedAfter:  &testTime2022,
			},
			page:       1,
			wantParams: "cve_id_year=1999&page=1&state=REJECT&time_modified.gt=2022-01-01T00%3A00%3A00Z&time_modified.lt=1992-01-01T00%3A00%3A00Z&time_reserved.gt=2000-01-01T00%3A00%3A00Z&time_reserved.lt=1999-01-01T00%3A00%3A00Z",
		},
		{
			opts: ListOptions{
				State: cveschema.StatePublic,
				Year:  2000,
			},
			page:       2,
			wantParams: "cve_id_year=2000&page=2&state=PUBLIC",
		},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("State=%s/Year=%d/ReservedBefore=%s/ReservedAfter=%s/ModifiedBefore=%s/ModifiedAfter=%s", test.opts.State, test.opts.Year, test.opts.ReservedBefore, test.opts.ReservedAfter, test.opts.ModifiedBefore, test.opts.ModifiedAfter), func(t *testing.T) {
			c, s := newTestClientAndServer(nil)
			defer s.Close()
			req, err := c.createListOrgCVEsRequest(&test.opts, test.page)
			if err != nil {
				t.Fatalf("unexpected error creating ListOrgCVEs request: %v", err)
			}
			if got, want := req.URL.RawQuery, test.wantParams; got != want {
				t.Errorf("incorrect request params: got %v, want %v", got, want)
			}
		})
	}
}

func TestListOrgCVEsMultiPage(t *testing.T) {
	extraCVE := newTestCVE("CVE-2000-1234", cveschema.StateReserved, "2000")
	mockResponses := []any{
		listOrgCVEsResponse{
			CurrentPage: 0,
			NextPage:    1,
			CVEs:        defaultTestCVEs,
		},
		listOrgCVEsResponse{
			CurrentPage: 1,
			NextPage:    -1,
			CVEs:        AssignedCVEList{extraCVE},
		},
	}

	c, s := newTestClientAndServer(
		newTestHandlerMultiPage(t, mockResponses, nil))
	defer s.Close()
	got, err := c.ListOrgCVEs(nil)
	if err != nil {
		t.Fatalf("unexpected error listing org cves: %v", err)
	}
	want := append(defaultTestCVEs, extraCVE)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
