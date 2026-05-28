package plugin

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	"ai-sec-check/common/runner"
	"ai-sec-check/internal/options"
)

type InfraGuardPlugin struct {
	config PluginConfig
}

func NewInfraGuardPlugin() *InfraGuardPlugin {
	return &InfraGuardPlugin{}
}

func (p *InfraGuardPlugin) Name() string {
	return "infra_scan"
}

func (p *InfraGuardPlugin) Category() string {
	return CategoryInfra
}

func (p *InfraGuardPlugin) Description() string {
	return "AI infrastructure vulnerability scanning (based on AI-Infra-Guard)"
}

func (p *InfraGuardPlugin) Init(config PluginConfig) error {
	p.config = config
	return nil
}

func (p *InfraGuardPlugin) Scan(ctx context.Context, target ScanTarget) (*ScanResult, error) {
	result := &ScanResult{
		PluginName: p.Name(),
		Category:   p.Category(),
		Target:     target.Value,
		Status:     StatusCompleted,
		Findings:   []Finding{},
	}

	fpDir := p.config.GetString("fps_dir")
	if fpDir == "" {
		fpDir = "data/fingerprints"
	}
	vulDir := p.config.GetString("vul_dir")
	if vulDir == "" {
		vulDir = "data/vuln"
	}

	if _, err := os.Stat(fpDir); os.IsNotExist(err) {
		result.Status = StatusFailed
		result.Summary = fmt.Sprintf("fingerprint templates not found: %s", fpDir)
		return result, nil
	}
	if _, err := os.Stat(vulDir); os.IsNotExist(err) {
		result.Status = StatusFailed
		result.Summary = fmt.Sprintf("vulnerability database not found: %s", vulDir)
		return result, nil
	}

	targetValue := strings.TrimSpace(target.Value)
	if targetValue == "" {
		result.Status = StatusFailed
		result.Summary = "target value cannot be empty"
		return result, nil
	}

	timeoutSec := p.config.GetInt("timeout")
	if timeoutSec <= 0 {
		timeoutSec = 300
	}
	rateLimit := p.config.GetInt("rate_limit")
	if rateLimit <= 0 {
		rateLimit = 50
	}

	opts := &options.Options{
		Target:      []string{targetValue},
		FPTemplates: fpDir,
		AdvTemplates: vulDir,
		TimeOut:     10,
		RateLimit:   rateLimit,
		Language:    "zh",
	}

	var mu sync.Mutex
	var scanResults []runner.CallbackScanResult
	var reportInfo *runner.CallbackReportInfo
	var errorTargets []string

	opts.SetCallback(func(data interface{}) {
		mu.Lock()
		defer mu.Unlock()
		switch v := data.(type) {
		case runner.CallbackScanResult:
			scanResults = append(scanResults, v)
			if v.Fingerprint != "" {
				ReportProgress(ctx, len(scanResults), 0, fmt.Sprintf("Found: %s at %s", v.Fingerprint, v.TargetURL))
			} else {
				ReportProgress(ctx, len(scanResults), 0, fmt.Sprintf("Scanned: %s", v.TargetURL))
			}
		case runner.CallbackReportInfo:
			reportInfo = &v
			ReportProgress(ctx, 100, 100, fmt.Sprintf("Scan complete, security score: %d", v.SecScore))
		case runner.CallbackErrorInfo:
			errorTargets = append(errorTargets, v.Target)
		}
	})

	scanDone := make(chan struct{})
	var runErr error

	go func() {
		defer close(scanDone)
		ReportProgress(ctx, 0, 0, "Loading fingerprint and vulnerability databases...")
		r, err := runner.New(opts)
		if err != nil {
			runErr = fmt.Errorf("failed to create runner: %w", err)
			return
		}
		defer r.Close()
		ReportProgress(ctx, 0, 0, fmt.Sprintf("Scanning target: %s...", targetValue))
		r.RunEnumeration()
	}()

	select {
	case <-ctx.Done():
		result.Status = StatusPartial
		result.Summary = "infra scan interrupted by context cancellation"
		p.collectFindings(result, scanResults, reportInfo, errorTargets)
		return result, nil
	case <-scanDone:
	}

	if runErr != nil {
		result.Status = StatusFailed
		result.Summary = runErr.Error()
		return result, nil
	}

	p.collectFindings(result, scanResults, reportInfo, errorTargets)
	return result, nil
}

func (p *InfraGuardPlugin) collectFindings(
	result *ScanResult,
	scanResults []runner.CallbackScanResult,
	reportInfo *runner.CallbackReportInfo,
	errorTargets []string,
) {
	var findings []Finding
	var rawParts []string

	for _, sr := range scanResults {
		rawParts = append(rawParts, fmt.Sprintf("%s [%d] %s fp=%s", sr.TargetURL, sr.StatusCode, sr.Title, sr.Fingerprint))

		if sr.Fingerprint != "" {
			findings = append(findings, Finding{
				Severity:    SeverityInfo,
				Title:       fmt.Sprintf("AI component detected: %s", sr.Fingerprint),
				Description: fmt.Sprintf("Target %s (status %d, title: %s) identified as: %s", sr.TargetURL, sr.StatusCode, sr.Title, sr.Fingerprint),
				RuleID:      "INFRA-FP-DETECT",
				Evidence:    fmt.Sprintf("url=%s, status=%d, fingerprint=%s", sr.TargetURL, sr.StatusCode, sr.Fingerprint),
				Remediation: "Verify this component is properly secured and up to date.",
				Source:      "infra_scan",
			})
		}

		for _, vul := range sr.Vulnerabilities {
			severity := mapInfraSeverity(vul.Severity)
			findings = append(findings, Finding{
				Severity:    severity,
				Title:       fmt.Sprintf("%s [%s]", vul.CVEName, vul.Severity),
				Description: fmt.Sprintf("%s\n%s", vul.Summary, vul.Details),
				RuleID:      vul.CVEName,
				Evidence:    fmt.Sprintf("target=%s, fingerprint=%s", sr.TargetURL, sr.Fingerprint),
				Remediation: vul.SecurityAdvise,
				Source:      "infra_scan",
			})
		}
	}

	if len(errorTargets) > 0 {
		rawParts = append(rawParts, fmt.Sprintf("Unreachable targets: %s", strings.Join(errorTargets, ", ")))
	}

	vulCount := 0
	highCount := 0
	for _, f := range findings {
		if f.Severity == SeverityCritical || f.Severity == SeverityHigh {
			highCount++
		}
		if f.RuleID != "INFRA-FP-DETECT" {
			vulCount++
		}
	}

	if reportInfo != nil {
		rawParts = append(rawParts, fmt.Sprintf("Security score: %d (high=%d, medium=%d, low=%d)",
			reportInfo.SecScore, reportInfo.HighRisk, reportInfo.MediumRisk, reportInfo.LowRisk))
	}

	result.Findings = findings
	result.RawOutput = strings.Join(rawParts, "\n")

	if vulCount > 0 {
		result.Summary = fmt.Sprintf("Infra scan: %d host(s) scanned, %d vulnerability(ies) found (%d high/critical), %d fingerprint(s) detected",
			len(scanResults), vulCount, highCount, len(findings)-vulCount)
	} else if len(scanResults) > 0 {
		result.Summary = fmt.Sprintf("Infra scan: %d host(s) scanned, no vulnerabilities found, %d fingerprint(s) detected",
			len(scanResults), len(findings))
	} else {
		result.Summary = "Infra scan: no hosts responded or target unreachable"
		if len(errorTargets) > 0 {
			result.Summary += fmt.Sprintf(" (%d unreachable)", len(errorTargets))
		}
	}
}

func mapInfraSeverity(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical", "严重":
		return SeverityCritical
	case "high", "高危":
		return SeverityHigh
	case "medium", "中危":
		return SeverityMedium
	case "low", "低危":
		return SeverityLow
	default:
		return SeverityInfo
	}
}

func (p *InfraGuardPlugin) IsAvailable() bool {
	fpDir := p.config.GetString("fps_dir")
	if fpDir == "" {
		fpDir = "data/fingerprints"
	}
	if _, err := os.Stat(fpDir); os.IsNotExist(err) {
		return false
	}
	vulDir := p.config.GetString("vul_dir")
	if vulDir == "" {
		vulDir = "data/vuln"
	}
	if _, err := os.Stat(vulDir); os.IsNotExist(err) {
		return false
	}
	return true
}

func (p *InfraGuardPlugin) ValidateTarget(target ScanTarget) error {
	switch target.Type {
	case TargetTypeURL, TargetTypeIP, TargetTypeCIDR:
		if strings.TrimSpace(target.Value) == "" {
			return fmt.Errorf("target value cannot be empty")
		}
		return nil
	default:
		return fmt.Errorf("unsupported target type: %s, expected url/ip/cidr", target.Type)
	}
}
