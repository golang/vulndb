// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package genai

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	gemini "github.com/google/generative-ai-go/genai"
	"google.golang.org/api/option"
)

type GeminiClient struct {
	model
	closer
}

type model interface {
	GenerateContent(ctx context.Context, parts ...gemini.Part) (*gemini.GenerateContentResponse, error)
}

type closer interface {
	Close() error
}

const (
	geminiAPIKeyEnv = "GEMINI_API_KEY"
	geminiModel     = "gemini-pro"
)

func NewGeminiClient(ctx context.Context) (*GeminiClient, error) {
	key := os.Getenv(geminiAPIKeyEnv)
	if key == "" {
		return nil, fmt.Errorf("%s must be set", geminiAPIKeyEnv)
	}
	client, err := gemini.NewClient(ctx, option.WithAPIKey(key))
	if err != nil {
		return nil, err
	}
	return &GeminiClient{
		model:  client.GenerativeModel(geminiModel),
		closer: client,
	}, nil
}

func (c *GeminiClient) GenerateText(ctx context.Context, prompt string) ([]string, error) {
	response, err := c.model.GenerateContent(ctx, gemini.Text(prompt))
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(response)
	if err == nil {
		fmt.Println(string(b))
	}
	var candidates []string
	for _, c := range response.Candidates {
		if c.Content != nil {
			for _, p := range c.Content.Parts {
				candidates = append(candidates, fmt.Sprintf("%s", p))
			}
		}
	}
	return candidates, nil
}
