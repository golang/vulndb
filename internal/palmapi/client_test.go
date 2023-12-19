// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package palmapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/google/generative-ai-go/genai"
	"google.golang.org/api/option"
)

func TestGenerateText(t *testing.T) {
	tests := []struct {
		name   string
		prompt string
		want   *GenerateTextResponse
	}{
		{
			name:   "no_response",
			prompt: "say hello",
			want:   &GenerateTextResponse{},
		},
		{
			name:   "response",
			prompt: "say hello",
			want: &GenerateTextResponse{
				Candidates: []TextCompletion{
					{
						Output: "hi!",
					},
					{
						Output: "hello there",
						Citations: Citation{
							Sources: []Source{
								{
									URI: "https://www.example.com",
								},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, cleanup, err := testClient(generateTextEndpoint, tt.prompt, tt.want)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(cleanup)
			got, err := c.GenerateText(tt.prompt)
			if err != nil {
				t.Fatalf("GenerateText() error = %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GenerateText() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGenerateTextError(t *testing.T) {
	tests := []struct {
		name    string
		prompt  string
		wantErr string
	}{
		{
			name:    "error",
			prompt:  "say hello",
			wantErr: "an error message",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, cleanup, err := testClientErr(generateTextEndpoint, tt.prompt, tt.wantErr)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(cleanup)
			_, err = c.GenerateText(tt.prompt)
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("GenerateText() error = %v; want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func testClient(endpoint, prompt string, response *GenerateTextResponse) (c *Client, cleanup func(), err error) {
	rBytes, err := json.Marshal(response)
	if err != nil {
		return nil, nil, err
	}
	handler := func(w http.ResponseWriter, r *http.Request) {
		writeErr := func(err error) {
			w.WriteHeader(http.StatusBadRequest)
			errJSON := fmt.Sprintf(`{"error":{"message":"%s"}}`, err)
			_, _ = w.Write([]byte(errJSON))
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeErr(err)
			return
		}

		var req GenerateTextRequest
		if err := json.Unmarshal(body, &req); err != nil {
			writeErr(err)
			return
		}

		if r.Method == http.MethodPost &&
			r.URL.Path == textBisonModel+":"+endpoint &&
			req.Prompt.Text == prompt {
			_, _ = w.Write(rBytes)
			return
		}

		writeErr(fmt.Errorf("Unrecognized endpoint (%s) or prompt (%s)", endpoint, prompt))
	}
	s := httptest.NewServer(http.HandlerFunc(handler))
	return NewClient(s.Client(), s.URL, getTestAPIKey), func() { s.Close() }, nil
}

func testClientErr(endpoint, prompt string, errMsg string) (c *Client, cleanup func(), err error) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		errJSON := fmt.Sprintf(`{"error":{"message":"%s"}}`, errMsg)
		_, _ = w.Write([]byte(errJSON))
	}
	s := httptest.NewServer(http.HandlerFunc(handler))
	return NewClient(s.Client(), s.URL, getTestAPIKey), func() { s.Close() }, nil
}

const testAPIKey = "TEST-API-KEY"

func getTestAPIKey() (string, error) {
	return testAPIKey, nil
}

func TestGemini(t *testing.T) {
	t.SkipNow()
	ctx := context.Background()
	client, err := genai.NewClient(ctx, option.WithAPIKey(os.Getenv("GEMINI_API_KEY")))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	m := client.GenerativeModel("gemini-pro")
	res, err := m.GenerateContent(ctx, genai.Text("something"))
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.MarshalIndent(res, "", "    ")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("%s\n", data)
}
