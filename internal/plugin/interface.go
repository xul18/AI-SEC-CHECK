package plugin

import "context"

type progressKey struct{}

type ProgressFunc func(current, total int, message string)

func WithProgress(ctx context.Context, fn ProgressFunc) context.Context {
	return context.WithValue(ctx, progressKey{}, fn)
}

func ReportProgress(ctx context.Context, current, total int, message string) {
	if fn, ok := ctx.Value(progressKey{}).(ProgressFunc); ok && fn != nil {
		fn(current, total, message)
	}
}

type ScannerPlugin interface {
	Name() string
	Category() string
	Description() string
	Init(config PluginConfig) error
	Scan(ctx context.Context, target ScanTarget) (*ScanResult, error)
	IsAvailable() bool
	ValidateTarget(target ScanTarget) error
}

type PluginConfig map[string]interface{}

func (c PluginConfig) GetString(key string) string {
	if v, ok := c[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func (c PluginConfig) GetInt(key string) int {
	if v, ok := c[key]; ok {
		if i, ok := v.(int); ok {
			return i
		}
		if f, ok := v.(float64); ok {
			return int(f)
		}
	}
	return 0
}

func (c PluginConfig) GetBool(key string) bool {
	if v, ok := c[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

func (c PluginConfig) GetStringSlice(key string) []string {
	if v, ok := c[key]; ok {
		if s, ok := v.([]string); ok {
			return s
		}
		if s, ok := v.([]interface{}); ok {
			result := make([]string, 0, len(s))
			for _, item := range s {
				if str, ok := item.(string); ok {
					result = append(result, str)
				}
			}
			return result
		}
	}
	return nil
}

type ScanTarget struct {
	Type     string            `json:"type"`
	Value    string            `json:"value"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

const (
	TargetTypeURL       = "url"
	TargetTypeIP        = "ip"
	TargetTypeCIDR      = "cidr"
	TargetTypeFile      = "file"
	TargetTypeText      = "text"
	TargetTypeAPI       = "api"
	TargetTypeMCPConfig = "mcp_config"
)

type ScanResult struct {
	ID         string    `json:"id"`
	PluginName string    `json:"plugin_name"`
	Category   string    `json:"category"`
	Target     string    `json:"target"`
	Status     string    `json:"status"`
	Findings   []Finding `json:"findings"`
	Summary    string    `json:"summary"`
	ScanTime   string    `json:"scan_time"`
	Duration   float64   `json:"duration_seconds"`
	RawOutput  string    `json:"raw_output,omitempty"`
}

const (
	StatusCompleted = "completed"
	StatusFailed    = "failed"
	StatusPartial   = "partial"
)

type Finding struct {
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
	RuleID      string `json:"rule_id"`
	Evidence    string `json:"evidence"`
	Remediation string `json:"remediation"`
	Source      string `json:"source"`
}

const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

const (
	CategoryContentSafety = "content_safety"
	CategoryModelSafety   = "model_safety"
	CategoryInfra         = "infra"
	CategoryMCP           = "mcp"
	CategoryAPI           = "api"
	CategoryRateLimit     = "ratelimit"
)
