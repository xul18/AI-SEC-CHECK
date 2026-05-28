package ai

import (
	"fmt"

	"ai-sec-check/internal/gologger"
	"ai-sec-check/internal/plugin"
)

type Manager struct {
	primary  AIProvider
	fallback AIProvider
	config   AIConfig
}

func NewManager(config AIConfig) *Manager {
	m := &Manager{
		fallback: NewFallbackProvider(),
		config:   config,
	}

	if config.Enabled {
		client := NewOpenAIClient(OpenAIConfig{
			BaseURL: config.BaseURL,
			APIKey:  config.APIKey,
			Model:   config.Model,
		})
		if client.IsAvailable() {
			m.primary = client
			gologger.Infof("AI assistant enabled: %s (%s)", config.Provider, config.BaseURL)
		} else {
			gologger.Warnf("AI assistant configured but unavailable, will use fallback")
		}
	} else {
		gologger.Infof("AI assistant disabled, using rule-based fallback")
	}

	return m
}

func (m *Manager) provider() AIProvider {
	if m.primary != nil && m.primary.IsAvailable() {
		return m.primary
	}
	return m.fallback
}

func (m *Manager) Analyze(results []*plugin.ScanResult) (string, error) {
	if m.primary != nil && m.primary.IsAvailable() {
		result, err := m.primary.Analyze(results)
		if err == nil {
			return result, nil
		}
		gologger.Warnf("AI primary provider failed, falling back: %v", err)
	}
	return m.fallback.Analyze(results)
}

func (m *Manager) GenerateReport(results []*plugin.ScanResult, format string) (string, error) {
	if m.primary != nil && m.primary.IsAvailable() {
		result, err := m.primary.GenerateReport(results, format)
		if err == nil {
			return result, nil
		}
		gologger.Warnf("AI primary provider failed, falling back: %v", err)
	}
	return m.fallback.GenerateReport(results, format)
}

func (m *Manager) SuggestFix(finding plugin.Finding) (string, error) {
	if m.primary != nil && m.primary.IsAvailable() {
		result, err := m.primary.SuggestFix(finding)
		if err == nil {
			return result, nil
		}
		gologger.Warnf("AI primary provider failed, falling back: %v", err)
	}
	return m.fallback.SuggestFix(finding)
}

func (m *Manager) Chat(question string, context string) (string, error) {
	if m.primary != nil && m.primary.IsAvailable() {
		result, err := m.primary.Chat(question, context)
		if err == nil {
			return result, nil
		}
		return "", fmt.Errorf("AI service error: %w", err)
	}
	return m.fallback.Chat(question, context)
}

func (m *Manager) IsAvailable() bool {
	return m.provider().IsAvailable()
}

func (m *Manager) IsAIEnabled() bool {
	return m.primary != nil && m.primary.IsAvailable()
}

func (m *Manager) CheckPrimaryConnection() error {
	if m.primary == nil {
		return fmt.Errorf("AI not configured")
	}
	return m.primary.CheckConnection()
}

func (m *Manager) GetModelName() string {
	if m.config.Model != "" {
		return m.config.Model
	}
	return "not configured"
}

func (m *Manager) GetBaseURL() string {
	return m.config.BaseURL
}

func (m *Manager) UpdateConfig(config AIConfig) {
	m.config = config
	if config.Enabled && config.BaseURL != "" {
		client := NewOpenAIClient(OpenAIConfig{
			BaseURL: config.BaseURL,
			APIKey:  config.APIKey,
			Model:   config.Model,
		})
		m.primary = client
	} else {
		m.primary = nil
	}
}
