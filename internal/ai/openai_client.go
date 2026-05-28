package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"ai-sec-check/internal/plugin"
)

type OpenAIClient struct {
	config OpenAIConfig
	client *http.Client
}

func NewOpenAIClient(config OpenAIConfig) *OpenAIClient {
	return &OpenAIClient{
		config: config,
		client: &http.Client{Timeout: 120 * time.Second},
	}
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model    string        `json:"model"`
	Messages []chatMessage `json:"messages"`
}

type chatChoice struct {
	Message chatMessage `json:"message"`
}

type chatResponse struct {
	Choices []chatChoice `json:"choices"`
}

func (c *OpenAIClient) CheckConnection() error {
	baseURL := strings.TrimRight(c.config.BaseURL, "/")
	url := baseURL + "/models"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	if c.config.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.config.APIKey)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("authentication failed: invalid API key")
	}
	if resp.StatusCode >= 500 {
		return fmt.Errorf("server error: HTTP %d", resp.StatusCode)
	}
	return nil
}

func (c *OpenAIClient) chat(systemPrompt, userPrompt string) (string, error) {
	baseURL := strings.TrimRight(c.config.BaseURL, "/")
	url := baseURL + "/chat/completions"

	reqBody := chatRequest{
		Model: c.config.Model,
		Messages: []chatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userPrompt},
		},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.config.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.config.APIKey)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	var chatResp chatResponse
	if err := json.Unmarshal(body, &chatResp); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if len(chatResp.Choices) == 0 {
		return "", fmt.Errorf("no response from model")
	}

	return chatResp.Choices[0].Message.Content, nil
}

func (c *OpenAIClient) Analyze(results []*plugin.ScanResult) (string, error) {
	resultsJSON, _ := json.MarshalIndent(results, "", "  ")
	systemPrompt := "You are an AI security analyst. Analyze the following scan results and provide a comprehensive risk assessment with prioritized findings and correlations."
	userPrompt := fmt.Sprintf("Analyze these scan results:\n\n%s", string(resultsJSON))
	return c.chat(systemPrompt, userPrompt)
}

func (c *OpenAIClient) GenerateReport(results []*plugin.ScanResult, format string) (string, error) {
	resultsJSON, _ := json.MarshalIndent(results, "", "  ")
	systemPrompt := fmt.Sprintf("You are an AI security report generator. Generate a detailed security assessment report in %s format. Include executive summary, detailed findings, risk ratings, and remediation recommendations.", format)
	userPrompt := fmt.Sprintf("Generate a security report based on these scan results:\n\n%s", string(resultsJSON))
	return c.chat(systemPrompt, userPrompt)
}

func (c *OpenAIClient) SuggestFix(finding plugin.Finding) (string, error) {
	findingJSON, _ := json.MarshalIndent(finding, "", "  ")
	systemPrompt := "You are an AI security expert. Provide specific, actionable remediation steps for the following security finding. Include code examples where applicable."
	userPrompt := fmt.Sprintf("Suggest a fix for this finding:\n\n%s", string(findingJSON))
	return c.chat(systemPrompt, userPrompt)
}

func (c *OpenAIClient) Chat(question string, context string) (string, error) {
	systemPrompt := "You are an AI security assistant for the AI-SEC-CHECK platform. Help users understand scan results, security risks, and remediation strategies."
	if context != "" {
		systemPrompt += "\n\nContext:\n" + context
	}
	return c.chat(systemPrompt, question)
}

func (c *OpenAIClient) IsAvailable() bool {
	if c.config.BaseURL == "" {
		return false
	}
	return true
}
