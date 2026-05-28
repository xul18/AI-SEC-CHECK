package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type McpSecPlugin struct {
	config PluginConfig
}

func NewMcpSecPlugin() *McpSecPlugin {
	return &McpSecPlugin{}
}

func (p *McpSecPlugin) Name() string {
	return "mcpsec"
}

func (p *McpSecPlugin) Category() string {
	return CategoryMCP
}

func (p *McpSecPlugin) Description() string {
	return "MCP (Model Context Protocol) security scanning (built-in Go scanner)"
}

func (p *McpSecPlugin) Init(config PluginConfig) error {
	p.config = config
	return nil
}

func (p *McpSecPlugin) Scan(ctx context.Context, target ScanTarget) (*ScanResult, error) {
	result := &ScanResult{
		PluginName: p.Name(),
		Category:   p.Category(),
		Target:     target.Value,
		Status:     StatusCompleted,
		Findings:   []Finding{},
	}

	var configData map[string]interface{}
	var rawParts []string

	if json.Valid([]byte(target.Value)) {
		if err := json.Unmarshal([]byte(target.Value), &configData); err != nil {
			result.Status = StatusFailed
			result.Summary = fmt.Sprintf("invalid MCP config JSON: %s", err.Error())
			return result, nil
		}
		rawParts = append(rawParts, "Parsed inline JSON config")
	} else {
		data, err := os.ReadFile(target.Value)
		if err != nil {
			result.Status = StatusFailed
			result.Summary = fmt.Sprintf("failed to read config file: %s", err.Error())
			return result, nil
		}
		if err := json.Unmarshal(data, &configData); err != nil {
			result.Status = StatusFailed
			result.Summary = fmt.Sprintf("invalid MCP config JSON: %s", err.Error())
			return result, nil
		}
		rawParts = append(rawParts, fmt.Sprintf("Parsed config file: %s", target.Value))
	}

	findings := p.analyzeConfig(configData, &rawParts)

	result.Findings = findings
	result.RawOutput = strings.Join(rawParts, "\n")

	if len(findings) > 0 {
		critical := 0
		high := 0
		medium := 0
		low := 0
		for _, f := range findings {
			switch f.Severity {
			case SeverityCritical:
				critical++
			case SeverityHigh:
				high++
			case SeverityMedium:
				medium++
			default:
				low++
			}
		}
		result.Summary = fmt.Sprintf("Found %d MCP security issue(s): %d critical, %d high, %d medium, %d low",
			len(findings), critical, high, medium, low)
	} else {
		result.Summary = "No MCP security issues found"
	}

	return result, nil
}

func (p *McpSecPlugin) analyzeConfig(config map[string]interface{}, rawParts *[]string) []Finding {
	var findings []Finding

	servers, ok := config["mcpServers"].(map[string]interface{})
	if !ok {
		findings = append(findings, Finding{
			Severity:    SeverityMedium,
			Title:       "Invalid MCP configuration format",
			Description: "Configuration does not contain a valid 'mcpServers' object. Expected format: {\"mcpServers\": {...}}",
			RuleID:      "MCP-INVALID-FORMAT",
			Evidence:    "missing or invalid mcpServers key",
			Remediation: "Ensure the configuration follows the MCP specification with a 'mcpServers' top-level key.",
			Source:      "mcpsec",
		})
		return findings
	}

	for name, serverConfig := range servers {
		server, ok := serverConfig.(map[string]interface{})
		if !ok {
			continue
		}
		*rawParts = append(*rawParts, fmt.Sprintf("Analyzing server: %s", name))
		serverFindings := p.analyzeServer(name, server)
		findings = append(findings, serverFindings...)
	}

	globalFindings := p.analyzeGlobalConfig(config)
	findings = append(findings, globalFindings...)

	return findings
}

func (p *McpSecPlugin) analyzeServer(name string, server map[string]interface{}) []Finding {
	var findings []Finding
	resource := fmt.Sprintf("mcpserver:%s", name)

	if _, hasCommand := server["command"]; hasCommand {
		findings = append(findings, p.checkCommandSecurity(name, server, resource)...)
	}

	if _, hasURL := server["url"]; hasURL {
		findings = append(findings, p.checkURLSecurity(name, server, resource)...)
	}

	findings = append(findings, p.checkAuthConfig(name, server, resource)...)
	findings = append(findings, p.checkTransportSecurity(name, server, resource)...)
	findings = append(findings, p.checkPermissions(name, server, resource)...)
	findings = append(findings, p.checkEnvSecurity(name, server, resource)...)
	findings = append(findings, p.checkRateLimiting(name, server, resource)...)
	findings = append(findings, p.checkLogging(name, server, resource)...)
	findings = append(findings, p.checkInputValidation(name, server, resource)...)

	return findings
}

func (p *McpSecPlugin) checkCommandSecurity(name string, server map[string]interface{}, resource string) []Finding {
	var findings []Finding
	cmd, _ := server["command"].(string)
	args, _ := server["args"].([]interface{})

	dangerousCommands := map[string]string{
		"rm": "File deletion command", "del": "File deletion command",
		"format": "Disk format command", "fdisk": "Disk partition command",
		"mkfs": "Filesystem format command", "dd": "Disk dump command",
		"chmod": "Permission change command", "chown": "Ownership change command",
		"sudo": "Privilege escalation command", "su": "User switch command",
		"curl": "Network transfer tool", "wget": "Network download tool",
		"nc": "Netcat - network utility", "ncat": "Netcat - network utility",
		"python": "Script interpreter", "python3": "Script interpreter",
		"node": "Script interpreter", "bash": "Shell interpreter",
		"sh": "Shell interpreter", "powershell": "Shell interpreter",
		"cmd": "Shell interpreter", "eval": "Code evaluation",
		"exec": "Code execution", "rundll32": "DLL execution",
	}

	if desc, dangerous := dangerousCommands[cmd]; dangerous {
		severity := SeverityHigh
		switch cmd {
		case "sudo", "su", "rm", "format", "fdisk":
			severity = SeverityCritical
		case "bash", "sh", "powershell", "cmd":
			severity = SeverityHigh
		default:
			severity = SeverityMedium
		}

		findings = append(findings, Finding{
			Severity:    severity,
			Title:       fmt.Sprintf("Potentially dangerous command: %s", cmd),
			Description: fmt.Sprintf("MCP server '%s' uses command '%s' which is classified as: %s. This could allow arbitrary command execution through the MCP protocol.", name, cmd, desc),
			RuleID:      "MCP01-001",
			Evidence:    resource,
			Remediation: "Use a dedicated, minimal command instead of general-purpose interpreters. If an interpreter is necessary, implement strict input validation and sandboxing.",
			Source:      "mcpsec",
		})
	}

	for _, arg := range args {
		argStr, _ := arg.(string)
		if strings.Contains(argStr, "-e") || strings.Contains(argStr, "--eval") ||
			strings.Contains(argStr, "-c") || strings.Contains(argStr, "--command") {
			findings = append(findings, Finding{
				Severity:    SeverityCritical,
				Title:       "Command execution flag detected in arguments",
				Description: fmt.Sprintf("MCP server '%s' command arguments include execution flag '%s', which could allow arbitrary code execution.", name, argStr),
				RuleID:      "MCP01-002",
				Evidence:    fmt.Sprintf("%s arg=%s", resource, argStr),
				Remediation: "Remove command execution flags from arguments. Use static configuration files instead of inline code execution.",
				Source:      "mcpsec",
			})
		}
	}

	return findings
}

func (p *McpSecPlugin) checkURLSecurity(name string, server map[string]interface{}, resource string) []Finding {
	var findings []Finding
	url, _ := server["url"].(string)

	if strings.HasPrefix(url, "http://") {
		findings = append(findings, Finding{
			Severity:    SeverityHigh,
			Title:       "Insecure HTTP transport",
			Description: fmt.Sprintf("MCP server '%s' uses insecure HTTP transport (url: %s). Data transmitted in plaintext could be intercepted.", name, url),
			RuleID:      "MCP02-001",
			Evidence:    fmt.Sprintf("%s url=%s", resource, url),
			Remediation: "Use HTTPS instead of HTTP to encrypt all communications between client and server.",
			Source:      "mcpsec",
		})
	}

	if strings.Contains(url, "localhost") || strings.Contains(url, "127.0.0.1") || strings.Contains(url, "0.0.0.0") {
		findings = append(findings, Finding{
			Severity:    SeverityMedium,
			Title:       "Local network binding detected",
			Description: fmt.Sprintf("MCP server '%s' is bound to a local address (%s). This may expose services on the local network.", name, url),
			RuleID:      "MCP02-002",
			Evidence:    fmt.Sprintf("%s url=%s", resource, url),
			Remediation: "Ensure local-only binding is intentional. Consider adding authentication even for local connections.",
			Source:      "mcpsec",
		})
	}

	return findings
}

func (p *McpSecPlugin) checkAuthConfig(name string, server map[string]interface{}, resource string) []Finding {
	var findings []Finding

	hasAuth := false
	if _, ok := server["authentication"]; ok {
		hasAuth = true
	}
	if _, ok := server["auth"]; ok {
		hasAuth = true
	}
	if headers, ok := server["headers"].(map[string]interface{}); ok {
		for k := range headers {
			if strings.Contains(strings.ToLower(k), "auth") || strings.Contains(strings.ToLower(k), "key") || strings.Contains(strings.ToLower(k), "token") {
				hasAuth = true
			}
		}
	}

	if !hasAuth {
		findings = append(findings, Finding{
			Severity:    SeverityCritical,
			Title:       "Missing authentication configuration",
			Description: fmt.Sprintf("MCP server '%s' has no authentication configuration, allowing unauthenticated access to all tools.", name),
			RuleID:      "MCP03-001",
			Evidence:    resource,
			Remediation: "Configure authentication using OAuth 2.0, API keys, or mTLS. Ensure all MCP server endpoints require valid credentials.",
			Source:      "mcpsec",
		})
	}

	return findings
}

func (p *McpSecPlugin) checkTransportSecurity(name string, server map[string]interface{}, resource string) []Finding {
	var findings []Finding

	if _, hasURL := server["url"]; hasURL {
		url, _ := server["url"].(string)
		if !strings.HasPrefix(url, "https://") {
			findings = append(findings, Finding{
				Severity:    SeverityHigh,
				Title:       "Unencrypted transport for remote server",
				Description: fmt.Sprintf("MCP server '%s' uses unencrypted transport. All data including prompts and responses could be intercepted.", name),
				RuleID:      "MCP04-001",
				Evidence:    resource,
				Remediation: "Configure TLS/HTTPS for all remote MCP server connections.",
				Source:      "mcpsec",
			})
		}
	}

	return findings
}

func (p *McpSecPlugin) checkPermissions(name string, server map[string]interface{}, resource string) []Finding {
	var findings []Finding

	if tools, ok := server["tools"].([]interface{}); ok {
		dangerousToolPatterns := []string{"exec", "shell", "system", "eval", "run", "execute",
			"delete", "remove", "drop", "write", "modify", "admin", "root", "sudo"}

		for _, t := range tools {
			toolMap, ok := t.(map[string]interface{})
			if !ok {
				continue
			}
			toolName, _ := toolMap["name"].(string)
			toolNameLower := strings.ToLower(toolName)

			for _, pattern := range dangerousToolPatterns {
				if strings.Contains(toolNameLower, pattern) {
					findings = append(findings, Finding{
						Severity:    SeverityHigh,
						Title:       fmt.Sprintf("Potentially dangerous tool: %s", toolName),
						Description: fmt.Sprintf("MCP server '%s' exposes tool '%s' which matches a dangerous pattern ('%s'). This tool could allow system-level operations.", name, toolName, pattern),
						RuleID:      "MCP05-001",
						Evidence:    fmt.Sprintf("%s tool=%s", resource, toolName),
						Remediation: "Review the tool's implementation. Apply the principle of least privilege and add confirmation prompts for destructive operations.",
						Source:      "mcpsec",
					})
					break
				}
			}
		}
	}

	return findings
}

func (p *McpSecPlugin) checkEnvSecurity(name string, server map[string]interface{}, resource string) []Finding {
	var findings []Finding

	if env, ok := server["env"].(map[string]interface{}); ok {
		sensitiveEnvKeys := []string{"PASSWORD", "SECRET", "TOKEN", "API_KEY", "PRIVATE_KEY",
			"ACCESS_KEY", "CREDENTIAL", "AUTH"}

		for key, value := range env {
			keyUpper := strings.ToUpper(key)
			for _, sensitive := range sensitiveEnvKeys {
				if strings.Contains(keyUpper, sensitive) {
					valStr, _ := value.(string)
					findings = append(findings, Finding{
						Severity:    SeverityCritical,
						Title:       fmt.Sprintf("Sensitive data in environment variables: %s", key),
						Description: fmt.Sprintf("MCP server '%s' has sensitive data in environment variable '%s'. Secrets in configuration files may be leaked through logs, error messages, or version control.", name, key),
						RuleID:      "MCP06-001",
						Evidence:    fmt.Sprintf("%s env_key=%s value_length=%d", resource, key, len(valStr)),
						Remediation: "Use a secrets manager or vault instead of embedding secrets in configuration. Reference secrets by name/path rather than value.",
						Source:      "mcpsec",
					})
					break
				}
			}
		}
	}

	return findings
}

func (p *McpSecPlugin) checkRateLimiting(name string, server map[string]interface{}, resource string) []Finding {
	var findings []Finding

	hasRateLimit := false
	if _, ok := server["rateLimit"]; ok {
		hasRateLimit = true
	}
	if _, ok := server["rate_limit"]; ok {
		hasRateLimit = true
	}
	if _, ok := server["throttle"]; ok {
		hasRateLimit = true
	}

	if !hasRateLimit {
		findings = append(findings, Finding{
			Severity:    SeverityMedium,
			Title:       "No rate limiting configured",
			Description: fmt.Sprintf("MCP server '%s' has no rate limiting, making it vulnerable to denial of service through resource exhaustion.", name),
			RuleID:      "MCP10-001",
			Evidence:    resource,
			Remediation: "Configure rate limiting with appropriate thresholds (requests per second) and payload size limits.",
			Source:      "mcpsec",
		})
	}

	return findings
}

func (p *McpSecPlugin) checkLogging(name string, server map[string]interface{}, resource string) []Finding {
	var findings []Finding

	hasLogging := false
	if _, ok := server["logging"]; ok {
		hasLogging = true
	}
	if _, ok := server["audit"]; ok {
		hasLogging = true
	}

	if !hasLogging {
		findings = append(findings, Finding{
			Severity:    SeverityMedium,
			Title:       "No logging configuration",
			Description: fmt.Sprintf("MCP server '%s' has no logging configuration, making it impossible to detect and investigate security incidents.", name),
			RuleID:      "MCP09-001",
			Evidence:    resource,
			Remediation: "Enable logging with at least 'info' level and enable audit logging for all tool invocations.",
			Source:      "mcpsec",
		})
	}

	return findings
}

func (p *McpSecPlugin) checkInputValidation(name string, server map[string]interface{}, resource string) []Finding {
	var findings []Finding

	if tools, ok := server["tools"].([]interface{}); ok {
		for _, t := range tools {
			toolMap, ok := t.(map[string]interface{})
			if !ok {
				continue
			}
			toolName, _ := toolMap["name"].(string)
			if _, hasSchema := toolMap["inputSchema"]; !hasSchema {
				if _, hasParams := toolMap["parameters"]; !hasParams {
					findings = append(findings, Finding{
						Severity:    SeverityMedium,
						Title:       fmt.Sprintf("Tool without input validation: %s", toolName),
						Description: fmt.Sprintf("MCP server '%s' tool '%s' has no input schema defined. Without validation, malformed or malicious inputs could cause unexpected behavior.", name, toolName),
						RuleID:      "MCP07-001",
						Evidence:    fmt.Sprintf("%s tool=%s", resource, toolName),
						Remediation: "Define JSON Schema for all tool inputs to enforce type checking, length limits, and pattern constraints.",
						Source:      "mcpsec",
					})
				}
			}
		}
	}

	return findings
}

func (p *McpSecPlugin) analyzeGlobalConfig(config map[string]interface{}) []Finding {
	var findings []Finding

	if _, ok := config["security"]; !ok {
		findings = append(findings, Finding{
			Severity:    SeverityMedium,
			Title:       "No global security policy defined",
			Description: "The MCP configuration does not define a global security policy. Security settings should be enforced at the configuration level.",
			RuleID:      "MCP08-001",
			Evidence:    "missing 'security' key",
			Remediation: "Add a 'security' section to the configuration with global policies for authentication, rate limiting, and audit logging.",
			Source:      "mcpsec",
		})
	}

	return findings
}

func (p *McpSecPlugin) IsAvailable() bool {
	return true
}

func (p *McpSecPlugin) ValidateTarget(target ScanTarget) error {
	if target.Type != TargetTypeMCPConfig && target.Type != TargetTypeFile && target.Type != TargetTypeText {
		return fmt.Errorf("unsupported target type: %s, expected mcp_config/file/text", target.Type)
	}
	if strings.TrimSpace(target.Value) == "" {
		return fmt.Errorf("target value cannot be empty")
	}
	return nil
}
