package ai

import "ai-sec-check/internal/plugin"

type AIProvider interface {
	Analyze(results []*plugin.ScanResult) (string, error)
	GenerateReport(results []*plugin.ScanResult, format string) (string, error)
	SuggestFix(finding plugin.Finding) (string, error)
	Chat(question string, context string) (string, error)
	IsAvailable() bool
	CheckConnection() error
}

type OpenAIConfig struct {
	BaseURL string `yaml:"base_url" json:"base_url"`
	APIKey  string `yaml:"api_key" json:"api_key"`
	Model   string `yaml:"model" json:"model"`
}

type AIConfig struct {
	Enabled            bool   `yaml:"enabled" json:"enabled"`
	Provider           string `yaml:"provider" json:"provider"`
	BaseURL            string `yaml:"base_url" json:"base_url"`
	APIKey             string `yaml:"api_key" json:"api_key"`
	Model              string `yaml:"model" json:"model"`
	FallbackToTemplate bool   `yaml:"fallback_to_template" json:"fallback_to_template"`
}
