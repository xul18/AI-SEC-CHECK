package ai

import (
	"fmt"
	"strings"

	"ai-sec-check/internal/plugin"
)

type FallbackProvider struct{}

func NewFallbackProvider() *FallbackProvider {
	return &FallbackProvider{}
}

func (f *FallbackProvider) Analyze(results []*plugin.ScanResult) (string, error) {
	var sb strings.Builder
	sb.WriteString("# AI-SEC-CHECK Security Assessment Report\n\n")
	sb.WriteString("*(AI analysis unavailable - using rule-based template)*\n\n")

	totalFindings := 0
	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0
	infoCount := 0

	for _, r := range results {
		totalFindings += len(r.Findings)
		for _, finding := range r.Findings {
			switch finding.Severity {
			case plugin.SeverityCritical:
				criticalCount++
			case plugin.SeverityHigh:
				highCount++
			case plugin.SeverityMedium:
				mediumCount++
			case plugin.SeverityLow:
				lowCount++
			default:
				infoCount++
			}
		}
	}

	sb.WriteString("## Executive Summary\n\n")
	sb.WriteString(fmt.Sprintf("- Total scans: %d\n", len(results)))
	sb.WriteString(fmt.Sprintf("- Total findings: %d\n", totalFindings))
	sb.WriteString(fmt.Sprintf("  - Critical: %d\n", criticalCount))
	sb.WriteString(fmt.Sprintf("  - High: %d\n", highCount))
	sb.WriteString(fmt.Sprintf("  - Medium: %d\n", mediumCount))
	sb.WriteString(fmt.Sprintf("  - Low: %d\n", lowCount))
	sb.WriteString(fmt.Sprintf("  - Info: %d\n", infoCount))

	overallRisk := "Low"
	if criticalCount > 0 {
		overallRisk = "Critical"
	} else if highCount > 0 {
		overallRisk = "High"
	} else if mediumCount > 0 {
		overallRisk = "Medium"
	}
	sb.WriteString(fmt.Sprintf("\n**Overall Risk Level: %s**\n\n", overallRisk))

	sb.WriteString("## Detailed Findings\n\n")
	for _, r := range results {
		sb.WriteString(fmt.Sprintf("### %s (%s)\n\n", r.PluginName, r.Category))
		sb.WriteString(fmt.Sprintf("- Target: %s\n", r.Target))
		sb.WriteString(fmt.Sprintf("- Status: %s\n", r.Status))
		sb.WriteString(fmt.Sprintf("- Duration: %.2fs\n\n", r.Duration))

		if len(r.Findings) > 0 {
			sb.WriteString("| Severity | Title | Rule ID |\n")
			sb.WriteString("|----------|-------|--------|\n")
			for _, f := range r.Findings {
				sb.WriteString(fmt.Sprintf("| %s | %s | %s |\n", f.Severity, f.Title, f.RuleID))
			}
			sb.WriteString("\n")
		} else {
			sb.WriteString("No findings.\n\n")
		}
	}

	return sb.String(), nil
}

func (f *FallbackProvider) GenerateReport(results []*plugin.ScanResult, format string) (string, error) {
	return f.Analyze(results)
}

func (f *FallbackProvider) SuggestFix(finding plugin.Finding) (string, error) {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# Remediation for: %s\n\n", finding.Title))
	sb.WriteString(fmt.Sprintf("**Severity:** %s\n\n", finding.Severity))
	sb.WriteString(fmt.Sprintf("**Description:** %s\n\n", finding.Description))

	if finding.Remediation != "" {
		sb.WriteString(fmt.Sprintf("**Recommended Fix:** %s\n", finding.Remediation))
	} else {
		sb.WriteString("**Recommended Fix:**\n")
		switch finding.Severity {
		case plugin.SeverityCritical:
			sb.WriteString("- This is a critical finding that requires immediate attention.\n")
			sb.WriteString("- Apply the vendor's security patch or upgrade to the latest version.\n")
			sb.WriteString("- Implement network segmentation to limit exposure.\n")
		case plugin.SeverityHigh:
			sb.WriteString("- Address this finding as soon as possible.\n")
			sb.WriteString("- Review and update access controls.\n")
			sb.WriteString("- Monitor for exploitation attempts.\n")
		case plugin.SeverityMedium:
			sb.WriteString("- Plan to address this finding in the near term.\n")
			sb.WriteString("- Implement additional security controls as compensating measures.\n")
		default:
			sb.WriteString("- Consider addressing this finding as part of routine maintenance.\n")
		}
	}

	return sb.String(), nil
}

func (f *FallbackProvider) Chat(question string, context string) (string, error) {
	return "AI 助手尚未配置。请在 AI Config 页面配置大模型连接信息（Base URL、Model 等）后重试。", nil
}

func (f *FallbackProvider) IsAvailable() bool {
	return true
}

func (f *FallbackProvider) CheckConnection() error {
	return fmt.Errorf("AI not configured")
}
