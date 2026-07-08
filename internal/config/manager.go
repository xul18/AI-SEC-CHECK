package config

import (
	"fmt"
	"os"
	"sync"

	"ai-sec-check/internal/ai"
	"ai-sec-check/internal/plugin"
	"gopkg.in/yaml.v3"
)

type ServerConfig struct {
	Addr string `yaml:"addr"`
}

type PluginItemConfig struct {
	Enabled bool                   `yaml:"enabled"`
	Options map[string]interface{} `yaml:",inline"`
}

type PluginsConfig struct {
	SensitiveWord PluginItemConfig `yaml:"sensitive_word"`
	Garak         PluginItemConfig `yaml:"garak"`
	GarakCustom   PluginItemConfig `yaml:"garak_custom"`
	InfraScan     PluginItemConfig `yaml:"infra_scan"`
	McpSec        PluginItemConfig `yaml:"mcpsec"`
	Autoswagger   PluginItemConfig `yaml:"autoswagger"`
	RateLimit     PluginItemConfig `yaml:"ratelimit"`
}

type AIConfig struct {
	Enabled           bool   `yaml:"enabled"`
	Provider          string `yaml:"provider"`
	BaseURL           string `yaml:"base_url"`
	APIKey            string `yaml:"api_key"`
	Model             string `yaml:"model"`
	FallbackToTemplate bool  `yaml:"fallback_to_template"`
}

type DatabaseConfig struct {
	Type string `yaml:"type"`
	Path string `yaml:"path"`
}

type ReportsConfig struct {
	OutputDir string   `yaml:"output_dir"`
	Formats   []string `yaml:"formats"`
}

type AppConfig struct {
	Server   ServerConfig   `yaml:"server"`
	Plugins  PluginsConfig  `yaml:"plugins"`
	AI       AIConfig       `yaml:"ai"`
	Database DatabaseConfig `yaml:"database"`
	Reports  ReportsConfig  `yaml:"reports"`
}

var (
	globalConfig *AppConfig
	configOnce   sync.Once
	configMu     sync.RWMutex
	configPath   string
)

func LoadConfig(path string) (*AppConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg AppConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	configMu.Lock()
	globalConfig = &cfg
	configPath = path
	configMu.Unlock()
	return &cfg, nil
}

func GetConfig() *AppConfig {
	configMu.RLock()
	defer configMu.RUnlock()
	return globalConfig
}

func (c *AppConfig) GetPluginConfig(name string) plugin.PluginConfig {
	configMu.RLock()
	defer configMu.RUnlock()

	var item PluginItemConfig
	switch name {
	case "sensitive_word":
		item = c.Plugins.SensitiveWord
	case "garak":
		item = c.Plugins.Garak
	case "garak_custom":
		item = c.Plugins.GarakCustom
	case "infra_scan":
		item = c.Plugins.InfraScan
	case "mcpsec":
		item = c.Plugins.McpSec
	case "autoswagger":
		item = c.Plugins.Autoswagger
	case "ratelimit":
		item = c.Plugins.RateLimit
	default:
		return plugin.PluginConfig{}
	}

	result := make(plugin.PluginConfig)
	result["enabled"] = item.Enabled
	for k, v := range item.Options {
		result[k] = v
	}
	if name == "garak" {
		if _, ok := result["api_key"]; !ok && c.AI.APIKey != "" {
			result["api_key"] = c.AI.APIKey
		}
		if _, ok := result["model_name"]; !ok && c.AI.Model != "" {
			result["model_name"] = c.AI.Model
		}
		if _, ok := result["base_url"]; !ok && c.AI.BaseURL != "" {
			result["base_url"] = c.AI.BaseURL
		}
	}
	return result
}

func (c *AppConfig) IsPluginEnabled(name string) bool {
	pcfg := c.GetPluginConfig(name)
	return pcfg.GetBool("enabled")
}

func (c *AppConfig) GetAIConfig() ai.AIConfig {
	configMu.RLock()
	defer configMu.RUnlock()
	return ai.AIConfig{
		Enabled:            c.AI.Enabled,
		Provider:           c.AI.Provider,
		BaseURL:            c.AI.BaseURL,
		APIKey:             c.AI.APIKey,
		Model:              c.AI.Model,
		FallbackToTemplate: c.AI.FallbackToTemplate,
	}
}

func SaveAIConfig(cfg ai.AIConfig) error {
	configMu.Lock()
	defer configMu.Unlock()

	if globalConfig == nil {
		return fmt.Errorf("config not loaded")
	}

	globalConfig.AI = AIConfig{
		Enabled:            cfg.Enabled,
		Provider:           cfg.Provider,
		BaseURL:            cfg.BaseURL,
		APIKey:             cfg.APIKey,
		Model:              cfg.Model,
		FallbackToTemplate: cfg.FallbackToTemplate,
	}

	if configPath == "" {
		return nil
	}

	data, err := yaml.Marshal(globalConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

func DefaultConfig() *AppConfig {
	return &AppConfig{
		Server: ServerConfig{
			Addr: "127.0.0.1:8088",
		},
		Plugins: PluginsConfig{
			SensitiveWord: PluginItemConfig{Enabled: true},
			Garak:         PluginItemConfig{Enabled: true},
			GarakCustom:   PluginItemConfig{Enabled: true},
			InfraScan:     PluginItemConfig{Enabled: true},
			McpSec:        PluginItemConfig{Enabled: true},
			Autoswagger:   PluginItemConfig{Enabled: true},
			RateLimit:     PluginItemConfig{Enabled: true},
		},
		AI: AIConfig{
			Enabled:           false,
			Provider:          "openai",
			FallbackToTemplate: true,
		},
		Database: DatabaseConfig{
			Type: "sqlite",
			Path: "data/aig.db",
		},
		Reports: ReportsConfig{
			OutputDir: "reports",
			Formats:   []string{"html", "json"},
		},
	}
}
