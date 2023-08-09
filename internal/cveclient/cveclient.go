// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package cveclient implements a client for interacting with MITRE CVE
// Services API as described at https://cveawg.mitre.org/api-docs/openapi.json.
package cveclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/vulndb/internal/cveschema5"
)

const (
	// ProdEndpoint is the production endpoint
	ProdEndpoint = "https://cveawg.mitre.org"
	// TestEndpoint is the test endpoint
	TestEndpoint = "https://cveawg-test.mitre.org"
	// DevEndpoint is the dev endpoint
	DevEndpoint = "https://cveawg-dev.mitre.org"

	// WebURL is the URL to view production CVE records on the web.
	WebURL = "https://www.cve.org"
	// TestWebURL is the URL to view test CVE records on the web.
	TestWebURL = "https://test.cve.org"
)

// Client is a MITRE CVE Services API client.
type Client struct {
	Config
	c *http.Client
}

// WebURL returns the URL that can be used to view a published
// CVE record on the web.
func (c *Client) WebURL(cveID string) string {
	baseURL := WebURL
	if c.Config.Endpoint == TestEndpoint {
		baseURL = TestWebURL
	}
	return fmt.Sprintf("%s/CVERecord?id=%s", baseURL, cveID)
}

// Config contains client configuration data.
type Config struct {
	// Endpoint is the endpoint to access when making API calls. Required.
	Endpoint string
	// Org is the shortname for the organization that is authenticated when
	// making API calls. Required.
	Org string
	// Key is the user's API key. Required.
	Key string
	// User is the username for the account that is making API calls. Required.
	User string
}

// New returns an initialized client configured via cfg.
func New(cfg Config) *Client {
	return &Client{cfg, http.DefaultClient}
}

// AssignedCVE contains information about an assigned CVE.
type AssignedCVE struct {
	ID          string           `json:"cve_id"`
	Year        string           `json:"cve_year"`
	State       cveschema5.State `json:"state"`
	CNA         string           `json:"owning_cna"`
	Reserved    time.Time        `json:"reserved"`
	RequestedBy RequestedBy      `json:"requested_by"`
}

// RequestedBy indicates the requesting user and organization for a CVE.
type RequestedBy struct {
	CNA  string `json:"cna"`
	User string `json:"user"`
}

func (c AssignedCVE) String() string {
	return fmt.Sprintf("%s: state=%s, cna=%s, requester=%s", c.ID, c.State, c.CNA, c.RequestedBy.User)
}

// AssignedCVEList is a list of AssignedCVEs.
type AssignedCVEList []AssignedCVE

// ShortString outputs a formatted string of newline-separated CVE IDs.
func (cs AssignedCVEList) ShortString() string {
	strs := []string{}
	for _, c := range cs {
		strs = append(strs, c.ID)
	}
	return strings.Join(strs, "\n")
}

// String outputs a formatted string of newline-separated CVE data.
func (cs AssignedCVEList) String() string {
	strs := []string{}
	for _, c := range cs {
		strs = append(strs, c.String())
	}
	return strings.Join(strs, "\n")
}

// ReserveOptions contains the configuration options for reserving new
// CVE IDs.
type ReserveOptions struct {
	// NumIDs is the number of CVE IDs to reserve. Required.
	NumIDs int
	// Year is the CVE ID year for new IDs, indicating the year the
	// vulnerability was discovered. Required.
	Year int
	// Mode indicates whether the block of CVEs should be in sequence.
	// Relevant only if NumIDs > 1.
	Mode RequestType
}

// RequestType is the type of CVE ID reserve request.
type RequestType string

const (
	// SequentialRequest requests CVE IDs be reserved in a sequential fashion.
	SequentialRequest RequestType = "sequential"
	// NonsequentialRequest requests CVE IDs be reserved in a nonsequential fashion.
	NonsequentialRequest RequestType = "nonsequential"
)

func (o *ReserveOptions) urlParams(org string) url.Values {
	params := url.Values{}
	params.Set("amount", fmt.Sprint(o.NumIDs))
	if o.Year != 0 {
		params.Set("cve_year", strconv.Itoa(o.Year))
	}
	params.Set("short_name", org)
	if o.NumIDs > 1 {
		params.Set("batch_type", string(o.Mode))
	}
	return params
}

func (c *Client) createReserveIDsRequest(opts ReserveOptions) (*http.Request, error) {
	req, err := c.createRequest(http.MethodPost,
		c.requestURL(cveIDTarget), nil)
	if err != nil {
		return nil, err
	}
	req.URL.RawQuery = opts.urlParams(c.Org).Encode()
	return req, err
}

type reserveIDsResponse struct {
	CVEs AssignedCVEList `json:"cve_ids"`
}

// ReserveIDs sends a request to the CVE API to reserve a block of CVE IDs.
// Returns a list of the reserved CVE IDs and their associated data.
// There may be fewer IDs than requested if, for example, the organization's
// quota is reached.
func (c *Client) ReserveIDs(opts ReserveOptions) (AssignedCVEList, error) {
	req, err := c.createReserveIDsRequest(opts)
	if err != nil {
		return nil, err
	}
	var assigned reserveIDsResponse
	checkStatus := func(s int) bool {
		return s == http.StatusOK || s == http.StatusPartialContent
	}
	err = c.sendRequest(req, checkStatus, &assigned)
	if err != nil {
		return nil, err
	}
	return assigned.CVEs, nil
}

// Quota contains information about an organizations reservation quota.
type Quota struct {
	Quota     int `json:"id_quota"`
	Reserved  int `json:"total_reserved"`
	Available int `json:"available"`
}

// RetrieveQuota queries the API for the organizations reservation quota.
func (c *Client) RetrieveQuota() (q *Quota, err error) {
	err = c.queryAPI(http.MethodGet, c.requestURL(orgTarget, c.Org, quotaTarget), nil, &q)
	return
}

// RetrieveID requests information about an assigned CVE ID.
func (c *Client) RetrieveID(id string) (cve *AssignedCVE, err error) {
	err = c.queryAPI(http.MethodGet, c.requestURL(cveIDTarget, id), nil, &cve)
	return
}

// RetrieveRecord requests a CVE record.
func (c *Client) RetrieveRecord(id string) (cve *cveschema5.CVERecord, err error) {
	err = c.queryAPI(http.MethodGet, c.requestURL(cveTarget, id), nil, &cve)
	return
}

func (c *Client) cveRecordEndpoint(cveID string) string {
	return c.requestURL(cveTarget, cveID, cnaTarget)
}

type recordRequestBody struct {
	CNAContainer cveschema5.CNAPublishedContainer `json:"cnaContainer"`
}
type createResponse struct {
	Created cveschema5.CVERecord `json:"created"`
}

func (c *Client) CreateRecord(id string, record *cveschema5.Containers) (*cveschema5.CVERecord, error) {
	requestBody := recordRequestBody{
		CNAContainer: record.CNAContainer,
	}
	var response createResponse
	err := c.queryAPI(http.MethodPost, c.cveRecordEndpoint(id), requestBody, &response)
	if err != nil {
		return nil, err
	}
	return &response.Created, nil
}

type updateResponse struct {
	Updated cveschema5.CVERecord `json:"updated"`
}

func (c *Client) UpdateRecord(id string, record *cveschema5.Containers) (*cveschema5.CVERecord, error) {
	requestBody := recordRequestBody{
		CNAContainer: record.CNAContainer,
	}
	var response updateResponse
	err := c.queryAPI(http.MethodPut, c.cveRecordEndpoint(id), requestBody, &response)
	if err != nil {
		return nil, err
	}
	return &response.Updated, nil
}

type Org struct {
	Name      string `json:"name"`
	ShortName string `json:"short_name"`
	UUID      string `json:"UUID"`
}

// RetrieveOrg requests information about an organization.
func (c *Client) RetrieveOrg() (org *Org, err error) {
	err = c.queryAPI(http.MethodGet, c.requestURL(orgTarget, c.Org), nil, &org)
	return
}

// ListOptions contains filters to be used when requesting a list of
// assigned CVEs.
type ListOptions struct {
	State          string
	Year           int
	ReservedBefore *time.Time
	ReservedAfter  *time.Time
	ModifiedBefore *time.Time
	ModifiedAfter  *time.Time
}

func (o ListOptions) String() string {
	var s []string
	if o.State != "" {
		s = append(s, fmt.Sprintf("state=%s", o.State))
	}
	if o.Year != 0 {
		s = append(s, fmt.Sprintf("year=%d", o.Year))
	}
	if o.ReservedBefore != nil {
		s = append(s, fmt.Sprintf("reserved_before=%s", o.ReservedBefore.Format(time.RFC3339)))
	}
	if o.ReservedAfter != nil {
		s = append(s, fmt.Sprintf("reserved_after=%s", o.ReservedAfter.Format(time.RFC3339)))
	}
	if o.ModifiedBefore != nil {
		s = append(s, fmt.Sprintf("modified_before=%s", o.ModifiedBefore.Format(time.RFC3339)))
	}
	if o.ModifiedAfter != nil {
		s = append(s, fmt.Sprintf("modified_after=%s", o.ModifiedAfter.Format(time.RFC3339)))
	}
	return strings.Join(s, ", ")
}

func (o *ListOptions) urlParams() url.Values {
	params := url.Values{}
	if o == nil {
		return params
	}
	if o.State != "" {
		params.Set("state", o.State)
	}
	if o.Year != 0 {
		params.Set("cve_id_year", strconv.Itoa(o.Year))
	}
	if o.ReservedBefore != nil {
		params.Set("time_reserved.lt", o.ReservedBefore.Format(time.RFC3339))
	}
	if o.ReservedAfter != nil {
		params.Set("time_reserved.gt", o.ReservedAfter.Format(time.RFC3339))
	}
	if o.ModifiedBefore != nil {
		params.Set("time_modified.lt", o.ModifiedBefore.Format(time.RFC3339))
	}
	if o.ModifiedAfter != nil {
		params.Set("time_modified.gt", o.ModifiedAfter.Format(time.RFC3339))
	}
	return params
}

type listOrgCVEsResponse struct {
	CurrentPage int             `json:"currentPage"`
	NextPage    int             `json:"nextPage"`
	CVEs        AssignedCVEList `json:"cve_ids"`
}

func (c Client) createListOrgCVEsRequest(opts *ListOptions, page int) (req *http.Request, err error) {
	req, err = c.createRequest(http.MethodGet, c.requestURL(cveIDTarget), nil)
	if err != nil {
		return nil, err
	}
	params := opts.urlParams()
	if page > 0 {
		params.Set("page", fmt.Sprint(page))
	}
	req.URL.RawQuery = params.Encode()
	return
}

// ListOrgCVEs requests information about the CVEs the organization has been
// assigned. This list can be filtered by setting the fields in opts.
func (c *Client) ListOrgCVEs(opts *ListOptions) (AssignedCVEList, error) {
	var cves []AssignedCVE
	page := 0
	for {
		req, err := c.createListOrgCVEsRequest(opts, page)
		if err != nil {
			return nil, err
		}
		var result listOrgCVEsResponse
		err = c.sendRequest(req, nil, &result)
		if err != nil {
			return nil, err
		}
		cves = append(cves, result.CVEs...)
		if result.NextPage <= result.CurrentPage {
			break
		}
		page = result.NextPage
	}
	return cves, nil
}

func (c *Client) queryAPI(method, url string, requestBody any, response any) error {
	req, err := c.createRequest(method, url, requestBody)
	if err != nil {
		return err
	}
	err = c.sendRequest(req, nil, response)
	if err != nil {
		return err
	}
	return nil
}

var (
	headerApiUser = "CVE-API-USER"
	headerApiOrg  = "CVE-API-ORG"
	headerApiKey  = "CVE-API-KEY"
)

// createRequest creates a new HTTP request and sets the header fields.
func (c *Client) createRequest(method, url string, body any) (*http.Request, error) {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, r)
	if err != nil {
		return nil, err
	}
	req.Header.Set(headerApiUser, c.User)
	req.Header.Set(headerApiOrg, c.Org)
	req.Header.Set(headerApiKey, c.Key)
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

// sendRequest sends an HTTP request, checks the returned status via
// checkStatus, and attempts to unmarshal the response into result.
// if checkStatus is nil, checks for http.StatusOK.
func (c *Client) sendRequest(req *http.Request, checkStatus func(int) bool, result any) (err error) {
	resp, err := c.c.Do(req)
	if err != nil {
		return fmt.Errorf("could not send HTTP request: %v", err)
	}
	defer resp.Body.Close()
	if checkStatus == nil {
		checkStatus = func(s int) bool {
			return s == http.StatusOK
		}
	}
	if !checkStatus(resp.StatusCode) {
		return fmt.Errorf("HTTP request %s %q returned error: %v", req.Method, req.URL, extractError(resp))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, result); err != nil {
		return err
	}
	return nil
}

var (
	cveTarget   = "cve"
	cveIDTarget = "cve-id"
	orgTarget   = "org"
	quotaTarget = "id_quota"
	cnaTarget   = "cna"
)

func (c *Client) requestURL(targets ...string) string {
	return fmt.Sprintf("%s/api/%s", c.Endpoint, strings.Join(targets, "/"))
}

type apiError struct {
	Error   string         `json:"error"`
	Message string         `json:"message"`
	Detail  apiErrorDetail `json:"details"`
}

type apiErrorDetail struct {
	Errors []apiErrorInner `json:"errors"`
}

type apiErrorInner struct {
	InstancePath string `json:"instancePath"`
	Message      string `json:"message"`
}

// extractError extracts additional error messages from the HTTP response
// if available, and wraps them into a single error.
func extractError(resp *http.Response) error {
	errMsg := resp.Status
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("%s: could not read error data: %s", errMsg, err)
	}
	var apiErr apiError
	if err := json.Unmarshal(body, &apiErr); err != nil {
		return fmt.Errorf("%s: could not unmarshal error: %s", errMsg, err)
	}

	// Append the error and message text if they add extra information
	// beyond the HTTP status text.
	statusText := strings.ToLower(http.StatusText(resp.StatusCode))
	for _, errText := range []string{apiErr.Error, apiErr.Message} {
		if errText != "" && strings.ToLower(errText) != statusText {
			errMsg = fmt.Sprintf("%s: %s", errMsg, errText)
		}
	}

	for _, detail := range apiErr.Detail.Errors {
		errMsg = fmt.Sprintf("%s\n  %s: %s", errMsg, detail.InstancePath, detail.Message)
	}

	return fmt.Errorf(errMsg)
}
