package ai

import (
	"regexp"
	"strings"
	"unicode"
)

type ScanIntent struct {
	Detected    bool   `json:"detected"`
	PluginName  string `json:"plugin_name,omitempty"`
	TargetType  string `json:"target_type,omitempty"`
	TargetValue string `json:"target_value,omitempty"`
	OriginalMsg string `json:"original_msg,omitempty"`
}

var urlPattern = regexp.MustCompile(`(?i)https?://[a-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+`)
var ipPortPattern = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b`)

type intentRule struct {
	Keywords   []string
	PluginName string
	TargetType string
}

var intentRules = []intentRule{
	{
		Keywords:   []string{"api授权", "api漏洞", "swagger", "openapi", "接口安全", "接口授权", "未授权访问", "api安全", "接口漏洞"},
		PluginName: "autoswagger",
		TargetType: "url",
	},
	{
		Keywords:   []string{"基础设施", "infra", "漏洞扫描", "安全漏洞", "服务漏洞", "端口扫描", "组件漏洞", "中间件漏洞", "框架漏洞"},
		PluginName: "infra_scan",
		TargetType: "url",
	},
	{
		Keywords:   []string{"越狱", "jailbreak", "提示注入", "prompt inject", "模型安全", "模型攻击", "红队", "redteam"},
		PluginName: "garak",
		TargetType: "url",
	},
	{
		Keywords:   []string{"mcp安全", "mcp配置", "mcp漏洞", "mcp扫描", "mcpsec"},
		PluginName: "mcpsec",
		TargetType: "mcp_config",
	},
	{
		Keywords:   []string{"限流", "熔断", "rate limit", "ratelimit", "压测", "压力测试", "并发测试", "负载测试"},
		PluginName: "ratelimit",
		TargetType: "url",
	},
	{
		Keywords:   []string{"敏感词", "内容安全", "敏感内容", "违禁词", "内容检测", "文本安全"},
		PluginName: "sensitive_word",
		TargetType: "text",
	},
}

var generalScanKeywords = []string{
	"扫描", "检查", "检测", "测试", "scan", "check", "detect", "test",
	"安全", "漏洞", "风险", "vulnerability", "security",
}

func ParseScanIntent(message string) ScanIntent {
	msgLower := strings.ToLower(message)

	var targetURL string
	if m := urlPattern.FindString(msgLower); m != "" {
		targetURL = cleanURL(m)
	} else if m := ipPortPattern.FindString(msgLower); m != "" {
		targetURL = "http://" + m
	}

	hasGeneralIntent := false
	for _, kw := range generalScanKeywords {
		if strings.Contains(msgLower, kw) {
			hasGeneralIntent = true
			break
		}
	}

	if !hasGeneralIntent && targetURL == "" {
		return ScanIntent{Detected: false, OriginalMsg: message}
	}

	for _, rule := range intentRules {
		for _, kw := range rule.Keywords {
			if strings.Contains(msgLower, kw) {
				intent := ScanIntent{
					Detected:    true,
					PluginName:  rule.PluginName,
					TargetType:  rule.TargetType,
					TargetValue: targetURL,
					OriginalMsg: message,
				}
				if intent.TargetValue == "" && rule.TargetType == "text" {
					intent.TargetValue = extractTextContent(message)
				}
				return intent
			}
		}
	}

	if targetURL != "" && hasGeneralIntent {
		return ScanIntent{
			Detected:    true,
			PluginName:  "infra_scan",
			TargetType:  "url",
			TargetValue: targetURL,
			OriginalMsg: message,
		}
	}

	return ScanIntent{Detected: false, OriginalMsg: message}
}

func extractTextContent(message string) string {
	separators := []string{"：", ":", "是", "为", "内容是", "文本是", "如下"}
	for _, sep := range separators {
		if idx := strings.Index(message, sep); idx >= 0 {
			content := strings.TrimSpace(message[idx+len(sep):])
			if content != "" {
				return content
			}
		}
	}
	return message
}

func cleanURL(raw string) string {
	raw = strings.TrimRightFunc(raw, func(r rune) bool {
		return unicode.Is(unicode.Po, r) || unicode.Is(unicode.Pf, r) || unicode.Is(unicode.Pi, r) || r == '/' || r == '\\'
	})
	return raw
}
