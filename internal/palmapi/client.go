// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package palmapi provides a client and utilities for interacting with
// the PaLM API (https://developers.generativeai.google/guide/palm_api_overview).
package palmapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

type Client struct {
	c         *http.Client
	url       string
	getAPIKey func() (string, error)
}

// NewDefaultClient returns a new default client for the PaLM API that reads
// an API key from the environment variable "PALM_API_KEY".
func NewDefaultClient() *Client {
	const (
		defaultURL = `https://generativelanguage.googleapis.com`
		apiKeyEnv  = "PALM_API_KEY"
	)
	return NewClient(http.DefaultClient, defaultURL, func() (string, error) {
		key := os.Getenv(apiKeyEnv)
		if key == "" {
			return "", fmt.Errorf("PaLM API key (env var %s) not set. You can get an API key at https://makersuite.google.com/app/apikey", apiKeyEnv)
		}
		return key, nil
	})
}

func NewClient(httpClient *http.Client, url string, getAPIKey func() (string, error)) *Client {
	return &Client{
		c:         httpClient,
		url:       url,
		getAPIKey: getAPIKey}
}

const generateTextEndpoint = "generateText"
const textBisonModel = "/v1beta3/models/text-bison-001"

// GenerateText is a wrapper for the PaLM API "generateText" endpoint.
// See https://developers.generativeai.google/api/rest/generativelanguage/models/generateText.
func (c *Client) GenerateText(prompt string) (*GenerateTextResponse, error) {
	reqBody, err := toRequestBody(prompt)
	if err != nil {
		return nil, err
	}
	key, err := c.getAPIKey()
	if err != nil {
		return nil, err
	}
	resp, err := http.Post(fmt.Sprintf("%s%s:%s?key=%s", c.url, textBisonModel, generateTextEndpoint, key), "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("PaLM API returned non-OK status %s", resp.Status)
		if msg, err2 := getErrMsg(resp.Body); err2 == nil {
			return nil, fmt.Errorf("%w: %s", err, msg)
		}
		return nil, err
	}
	return parseGenerateTextResponse(resp.Body)
}

func getErrMsg(r io.Reader) (string, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}
	var errResponse struct {
		Err struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(b, &errResponse); err != nil {
		return "", err
	}
	return errResponse.Err.Message, nil
}

// See https://developers.generativeai.google/api/rest/generativelanguage/GenerateTextResponse
type GenerateTextResponse struct {
	Candidates []TextCompletion `json:"candidates"`
	// Fields "filters" and "safetyFeedback" omitted.
}

// See https://developers.generativeai.google/api/rest/generativelanguage/GenerateTextResponse#TextCompletion
type TextCompletion struct {
	Output string `json:"output"`
	// Field "safetyRatings" omitted.
	Citations Citation `json:"citationMetadata,omitempty"`
}

// See https://developers.generativeai.google/api/rest/generativelanguage/CitationMetadata
type Citation struct {
	Sources []Source `json:"citationSources,omitempty"`
}

// See https://developers.generativeai.google/api/rest/generativelanguage/CitationMetadata#CitationSource
type Source struct {
	StartIndex int    `json:"startIndex,omitempty"`
	EndIndex   int    `json:"endIndex,omitempty"`
	URI        string `json:"uri,omitempty"`
	License    string `json:"license,omitempty"`
}

func parseGenerateTextResponse(r io.Reader) (*GenerateTextResponse, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var response GenerateTextResponse
	if err := json.Unmarshal(b, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

// See https://developers.generativeai.google/api/rest/generativelanguage/models/generateText#request-body
type GenerateTextRequest struct {
	Prompt          TextPrompt      `json:"prompt"`
	Temperature     float32         `json:"temperature,omitempty"`
	CandidateCount  int             `json:"candidateCount,omitempty"`
	TopK            int             `json:"topK,omitempty"`
	TopP            float32         `json:"topP,omitempty"`
	MaxOutputTokens int             `json:"maxOutputTokens,omitempty"`
	StopSequences   []string        `json:"stopSequences,omitempty"`
	SafetySettings  []SafetySetting `json:"safetySettings,omitempty"`
}

// See https://developers.generativeai.google/api/rest/generativelanguage/TextPrompt
type TextPrompt struct {
	Text string `json:"text"`
}

// See https://developers.generativeai.google/api/rest/generativelanguage/SafetySetting
type SafetySetting struct {
	Category  string `json:"category,omitempty"`
	Threshold int    `json:"threshold,omitempty"`
}

func toRequestBody(promptText string) ([]byte, error) {
	req := GenerateTextRequest{
		Prompt: TextPrompt{
			Text: promptText,
		},
		CandidateCount: 8, // max
		// Use a low temperature (max is 1.0) to allow less creativity.
		Temperature:    0.35,
		SafetySettings: blockNone(),
	}
	b, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func blockNone() []SafetySetting {
	return []SafetySetting{
		{
			Category:  "HARM_CATEGORY_DEROGATORY",
			Threshold: 4,
		},
		{
			Category:  "HARM_CATEGORY_TOXICITY",
			Threshold: 4,
		},
		{
			Category:  "HARM_CATEGORY_VIOLENCE",
			Threshold: 4,
		},
		{
			Category:  "HARM_CATEGORY_SEXUAL",
			Threshold: 4,
		},
		{
			Category:  "HARM_CATEGORY_MEDICAL",
			Threshold: 4,
		},
		{
			Category:  "HARM_CATEGORY_DANGEROUS",
			Threshold: 4,
		},
	}
}
