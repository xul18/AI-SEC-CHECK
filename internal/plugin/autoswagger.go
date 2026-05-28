package plugin

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type AutoswaggerPlugin struct {
	config    PluginConfig
	client    *http.Client
	apiKeyPatterns map[string]*regexp.Regexp
	piiPatterns   map[string]*regexp.Regexp
}

func NewAutoswaggerPlugin() *AutoswaggerPlugin {
	return &AutoswaggerPlugin{}
}

func (p *AutoswaggerPlugin) Name() string {
	return "autoswagger"
}

func (p *AutoswaggerPlugin) Category() string {
	return CategoryAPI
}

func (p *AutoswaggerPlugin) Description() string {
	return "API authorization vulnerability scanning (built-in Swagger/OpenAPI scanner)"
}

func (p *AutoswaggerPlugin) Init(config PluginConfig) error {
	p.config = config
	timeout := time.Duration(config.GetInt("timeout")) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	p.client = &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:        20,
			MaxIdleConnsPerHost: 5,
			IdleConnTimeout:     10 * time.Second,
		},
	}
	p.initPatterns()
	return nil
}

func (p *AutoswaggerPlugin) initPatterns() {
	p.apiKeyPatterns = map[string]*regexp.Regexp{
		"AWS API Key":       regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		"GitHub Token":      regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{36}`),
		"Stripe API Key":    regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24}`),
		"RSA Private Key":   regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`),
		"SSH Private Key":   regexp.MustCompile(`-----BEGIN OPENSSH PRIVATE KEY-----`),
		"PGP Private Key":   regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----`),
		"Slack Token":       regexp.MustCompile(`xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}`),
		"Google API Key":    regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
		"JWT Token":         regexp.MustCompile(`eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+`),
		"Generic Secret":    regexp.MustCompile(`(?i)(password|passwd|secret|token|api_key|apikey|access_key)\s*[:=]\s*['"]?[A-Za-z0-9\-_]{8,}`),
	}
	p.piiPatterns = map[string]*regexp.Regexp{
		"Email":      regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
		"Phone":      regexp.MustCompile(`(?:(?:\+?86)?\s*-?)?(?:1[3-9]\d{9})`),
		"ID Card":    regexp.MustCompile(`[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]`),
		"Credit Card": regexp.MustCompile(`\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})\b`),
	}
}

func (p *AutoswaggerPlugin) Scan(ctx context.Context, target ScanTarget) (*ScanResult, error) {
	result := &ScanResult{
		PluginName: p.Name(),
		Category:   p.Category(),
		Target:     target.Value,
		Status:     StatusCompleted,
		Findings:   []Finding{},
	}

	targetURL := strings.TrimRight(target.Value, "/")
	if !strings.HasPrefix(targetURL, "http") {
		targetURL = "http://" + targetURL
	}

	baseURL := p.extractBaseURL(targetURL)

	var allFindings []Finding
	var rawOutputs []string
	totalEndpoints := 0
	unauthEndpoints := 0

	swaggerDoc, swaggerURL := p.discoverSwaggerSpec(ctx, baseURL)
	if swaggerDoc == nil {
		swaggerDoc, swaggerURL = p.discoverFromTargetURL(ctx, targetURL, baseURL)
	}
	if swaggerDoc == nil {
		swaggerDoc, swaggerURL = p.discoverSwaggerUI(ctx, baseURL)
	}

	if swaggerDoc != nil {
		rawOutputs = append(rawOutputs, fmt.Sprintf("Found OpenAPI spec at: %s", swaggerURL))
		ReportProgress(ctx, 0, 0, fmt.Sprintf("Discovered OpenAPI spec at: %s", swaggerURL))
		if swaggerDoc.Info.Title != "" {
			rawOutputs = append(rawOutputs, fmt.Sprintf("API Title: %s (version: %s)", swaggerDoc.Info.Title, swaggerDoc.Info.Version))
		}
	}

	specEndpoints := []apiEndpoint{}
	if swaggerDoc != nil {
		specEndpoints = p.extractPathsFromSpec(swaggerDoc)
		rawOutputs = append(rawOutputs, fmt.Sprintf("Extracted %d endpoint(s) from spec", len(specEndpoints)))
	}

	commonEndpoints := p.getCommonEndpoints()

	allEndpoints := p.mergeEndpoints(specEndpoints, commonEndpoints)
	totalEndpoints = len(allEndpoints)
	rawOutputs = append(rawOutputs, fmt.Sprintf("Total: %d endpoint(s) to test (%d from spec + %d common)", totalEndpoints, len(specEndpoints), totalEndpoints-len(specEndpoints)))

	for i, ep := range allEndpoints {
		ReportProgress(ctx, i+1, totalEndpoints, fmt.Sprintf("Testing endpoint [%d/%d]: %s %s", i+1, totalEndpoints, ep.Method, ep.Path))
		select {
		case <-ctx.Done():
			result.Status = StatusPartial
			result.Summary = fmt.Sprintf("Scan interrupted: %d endpoint(s) tested, %d unauthorized", unauthEndpoints, unauthEndpoints)
			result.Findings = allFindings
			result.RawOutput = strings.Join(rawOutputs, "\n")
			return result, nil
		default:
		}

		epFindings := p.testEndpoint(ctx, baseURL, ep)
		if len(epFindings) > 0 {
			unauthEndpoints++
			allFindings = append(allFindings, epFindings...)
		}
	}

	if unauthEndpoints > 0 {
		result.Summary = fmt.Sprintf("API scan: %d endpoint(s) tested, %d unauthorized/sensitive access issue(s) found, %d total finding(s)",
			totalEndpoints, unauthEndpoints, len(allFindings))
	} else if totalEndpoints > 0 {
		result.Summary = fmt.Sprintf("API scan: %d endpoint(s) tested, no authorization issues found", totalEndpoints)
	} else {
		result.Summary = "API scan: no endpoints discovered or accessible"
	}

	result.Findings = allFindings
	result.RawOutput = strings.Join(rawOutputs, "\n")
	return result, nil
}

func (p *AutoswaggerPlugin) extractBaseURL(url string) string {
	lower := strings.ToLower(url)
	swaggerPaths := []string{
		"/swagger-ui/index.html", "/swagger-ui.html", "/swagger-ui/",
		"/docs/index.html", "/docs/", "/api-docs/",
		"/redoc", "/rapidoc", "/scalar",
	}
	for _, sp := range swaggerPaths {
		if strings.HasSuffix(lower, sp) {
			return url[:len(url)-len(sp)]
		}
	}

	if strings.Contains(lower, "/swagger") || strings.Contains(lower, "/openapi") || strings.Contains(lower, "/api-docs") {
		u := url
		idx := strings.Index(u, "/swagger")
		if idx == -1 {
			idx = strings.Index(u, "/openapi")
		}
		if idx == -1 {
			idx = strings.Index(u, "/api-docs")
		}
		if idx > 0 {
			schemeEnd := strings.Index(u, "://")
			if schemeEnd > 0 {
				nextSlash := strings.Index(u[schemeEnd+3:], "/")
				if nextSlash > 0 {
					return u[:schemeEnd+3+nextSlash]
				}
			}
		}
	}

	return url
}

func (p *AutoswaggerPlugin) discoverFromTargetURL(ctx context.Context, targetURL, baseURL string) (*swaggerSpec, string) {
	if baseURL == targetURL {
		return nil, ""
	}

	resp, err := p.fetchURL(ctx, targetURL, "text/html, */*")
	if err != nil {
		return nil, ""
	}
	if resp.statusCode != 200 {
		return nil, ""
	}

	if !strings.Contains(resp.contentType, "text/html") && !strings.Contains(resp.body, "<") {
		return nil, ""
	}

	ReportProgress(ctx, 0, 0, fmt.Sprintf("Target URL appears to be a documentation page, extracting API spec..."))

	specURLs := p.extractSpecURLsFromHTML(resp.body, baseURL)
	for _, specURL := range specURLs {
		spec := p.fetchSpec(ctx, specURL)
		if spec != nil && len(spec.Paths) > 0 {
			return spec, specURL
		}
	}

	inlineSpec := p.extractInlineSpec(resp.body)
	if inlineSpec != nil && len(inlineSpec.Paths) > 0 {
		return inlineSpec, targetURL + " (inline spec)"
	}

	return nil, ""
}

type fetchResult struct {
	statusCode  int
	contentType string
	body        string
}

func (p *AutoswaggerPlugin) fetchURL(ctx context.Context, url, accept string) (*fetchResult, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("User-Agent", "AI-SEC-CHECK/1.0")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	resp.Body.Close()
	if err != nil {
		return nil, err
	}

	return &fetchResult{
		statusCode:  resp.StatusCode,
		contentType: resp.Header.Get("Content-Type"),
		body:        string(body),
	}, nil
}

type swaggerSpec struct {
	Paths map[string]map[string]any `json:"paths"`
	Info  struct {
		Title   string `json:"title"`
		Version string `json:"version"`
	} `json:"info"`
	Servers []struct {
		URL string `json:"url"`
	} `json:"servers"`
}

type apiEndpoint struct {
	Method      string
	Path        string
	Description string
}

func (p *AutoswaggerPlugin) discoverSwaggerSpec(ctx context.Context, baseURL string) (*swaggerSpec, string) {
	specURLs := []string{
		"/swagger.json",
		"/swagger/v1/swagger.json",
		"/swagger/v2/swagger.json",
		"/v1/swagger.json",
		"/v2/swagger.json",
		"/v3/swagger.json",
		"/api-docs",
		"/api-docs/json",
		"/api-docs/swagger.json",
		"/api/swagger.json",
		"/api/v1/swagger.json",
		"/api/v2/swagger.json",
		"/openapi.json",
		"/openapi.yaml",
		"/.well-known/openapi.json",
		"/docs/swagger.json",
		"/docs/api-docs",
	}

	for _, specPath := range specURLs {
		url := baseURL + specPath
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "AI-SEC-CHECK/1.0")

		resp, err := p.client.Do(req)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		if resp.StatusCode != 200 {
			continue
		}

		var spec swaggerSpec
		if err := json.Unmarshal(body, &spec); err != nil {
			continue
		}

		if len(spec.Paths) > 0 {
			return &spec, url
		}
	}

	return nil, ""
}

func (p *AutoswaggerPlugin) discoverSwaggerUI(ctx context.Context, baseURL string) (*swaggerSpec, string) {
	uiPaths := []string{
		"/swagger-ui.html",
		"/swagger-ui/",
		"/swagger-ui/index.html",
		"/docs/",
		"/docs/index.html",
		"/api-docs/",
		"/redoc",
		"/rapidoc",
		"/scalar",
	}

	for _, uiPath := range uiPaths {
		url := baseURL + uiPath
		resp, err := p.fetchURL(ctx, url, "text/html, */*")
		if err != nil || resp.statusCode != 200 {
			continue
		}

		if !strings.Contains(resp.contentType, "text/html") && !strings.Contains(resp.body, "<") {
			continue
		}

		ReportProgress(ctx, 0, 0, fmt.Sprintf("Found Swagger UI at: %s, extracting API spec...", url))

		specURLs := p.extractSpecURLsFromHTML(resp.body, baseURL)
		for _, specURL := range specURLs {
			spec := p.fetchSpec(ctx, specURL)
			if spec != nil && len(spec.Paths) > 0 {
				return spec, specURL
			}
		}

		inlineSpec := p.extractInlineSpec(resp.body)
		if inlineSpec != nil && len(inlineSpec.Paths) > 0 {
			return inlineSpec, url + " (inline spec)"
		}
	}

	return nil, ""
}

func (p *AutoswaggerPlugin) extractSpecURLsFromHTML(html, baseURL string) []string {
	var urls []string
	seen := map[string]bool{}

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)url\s*:\s*["']([^"']+)["']`),
		regexp.MustCompile(`(?i)specUrl\s*:\s*["']([^"']+)["']`),
		regexp.MustCompile(`(?i)spec\s*:\s*["']([^"']+)["']`),
		regexp.MustCompile(`(?i)apiDoc\s*:\s*["']([^"']+)["']`),
		regexp.MustCompile(`(?i)data-spec\s*=\s*["']([^"']+)["']`),
		regexp.MustCompile(`(?i)data-url\s*=\s*["']([^"']+)["']`),
		regexp.MustCompile(`href=["']([^"']*?\.(?:json|yaml|yml))["']`),
		regexp.MustCompile(`src=["']([^"']*?\.(?:json|yaml|yml))["']`),
	}

	urlBlacklist := map[string]bool{
		"swagger-ui-bundle.js": true, "swagger-ui-standalone-preset.js": true,
		"swagger-ui.css": true, "index.css": true,
	}

	for _, pat := range patterns {
		matches := pat.FindAllStringSubmatch(html, -1)
		for _, m := range matches {
			if len(m) < 2 {
				continue
			}
			u := m[1]
			if seen[u] {
				continue
			}

			lower := strings.ToLower(u)
			skip := false
			for bl := range urlBlacklist {
				if strings.Contains(lower, bl) {
					skip = true
					break
				}
			}
			if skip {
				continue
			}

			if strings.HasSuffix(lower, ".js") || strings.HasSuffix(lower, ".css") ||
				strings.HasSuffix(lower, ".png") || strings.HasSuffix(lower, ".ico") ||
				strings.HasSuffix(lower, ".svg") || strings.HasSuffix(lower, ".woff") ||
				strings.HasSuffix(lower, ".woff2") || strings.HasSuffix(lower, ".ttf") {
				continue
			}

			seen[u] = true
			if strings.HasPrefix(u, "http") {
				urls = append(urls, u)
			} else if strings.HasPrefix(u, "/") {
				urls = append(urls, baseURL+u)
			} else {
				urls = append(urls, baseURL+"/"+u)
			}
		}
	}

	defaultSpecPaths := []string{
		"/swagger.json",
		"/swagger/v1/swagger.json",
		"/swagger/v2/swagger.json",
		"/v1/swagger.json",
		"/v2/swagger.json",
		"/v3/swagger.json",
		"/openapi.json",
		"/api-docs",
		"/api-docs/json",
		"/api-docs/swagger.json",
		"/api/swagger.json",
		"/api/v1/swagger.json",
		"/api/v2/swagger.json",
		"/api/v3/swagger.json",
	}
	for _, sp := range defaultSpecPaths {
		if !seen[sp] {
			seen[sp] = true
			urls = append(urls, baseURL+sp)
		}
	}

	return urls
}

func (p *AutoswaggerPlugin) extractInlineSpec(html string) *swaggerSpec {
	re := regexp.MustCompile(`(?s)spec\s*:\s*(\{[^}]*openapi[^}]*\})`)
	matches := re.FindAllStringSubmatch(html, -1)
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		specStr := m[1]
		bracketCount := 0
		start := strings.Index(specStr, "{")
		if start == -1 {
			continue
		}
		end := start
		for i := start; i < len(specStr); i++ {
			if specStr[i] == '{' {
				bracketCount++
			} else if specStr[i] == '}' {
				bracketCount--
				if bracketCount == 0 {
					end = i + 1
					break
				}
			}
		}
		if end <= start {
			continue
		}
		jsonStr := specStr[start:end]
		var spec swaggerSpec
		if err := json.Unmarshal([]byte(jsonStr), &spec); err == nil && len(spec.Paths) > 0 {
			return &spec
		}
	}

	re2 := regexp.MustCompile(`(?s)\bopenapi\s*:\s*["']3\.`)
	if re2.MatchString(html) {
		startIdx := strings.Index(html, "{")
		for startIdx != -1 {
			bracketCount := 0
			endIdx := startIdx
			for i := startIdx; i < len(html); i++ {
				if html[i] == '{' {
					bracketCount++
				} else if html[i] == '}' {
					bracketCount--
					if bracketCount == 0 {
						endIdx = i + 1
						break
					}
				}
			}
			if endIdx > startIdx {
				chunk := html[startIdx:endIdx]
				if strings.Contains(chunk, "openapi") && strings.Contains(chunk, "paths") {
					var spec swaggerSpec
					if err := json.Unmarshal([]byte(chunk), &spec); err == nil && len(spec.Paths) > 0 {
						return &spec
					}
				}
			}
			nextIdx := strings.Index(html[endIdx:], "{")
			if nextIdx == -1 {
				break
			}
			startIdx = endIdx + nextIdx
		}
	}

	return nil
}

func (p *AutoswaggerPlugin) fetchSpec(ctx context.Context, url string) *swaggerSpec {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "AI-SEC-CHECK/1.0")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	resp.Body.Close()
	if err != nil {
		return nil
	}

	if resp.StatusCode != 200 {
		return nil
	}

	var spec swaggerSpec
	if err := json.Unmarshal(body, &spec); err != nil {
		return nil
	}

	return &spec
}

func (p *AutoswaggerPlugin) mergeEndpoints(specEndpoints, commonEndpoints []apiEndpoint) []apiEndpoint {
	seen := map[string]bool{}
	var result []apiEndpoint

	for _, ep := range specEndpoints {
		key := ep.Method + " " + ep.Path
		if !seen[key] {
			seen[key] = true
			result = append(result, ep)
		}
	}

	for _, ep := range commonEndpoints {
		key := ep.Method + " " + ep.Path
		if !seen[key] {
			seen[key] = true
			result = append(result, ep)
		}
	}

	return result
}

func (p *AutoswaggerPlugin) extractPathsFromSpec(spec *swaggerSpec) []apiEndpoint {
	var endpoints []apiEndpoint
	for path, methods := range spec.Paths {
		for method, details := range methods {
			upperMethod := strings.ToUpper(method)
			if upperMethod != "GET" && upperMethod != "POST" && upperMethod != "PUT" && upperMethod != "DELETE" && upperMethod != "PATCH" {
				continue
			}
			desc := ""
			if m, ok := details.(map[string]any); ok {
				if s, ok := m["summary"].(string); ok {
					desc = s
				}
				if s, ok := m["description"].(string); ok && desc == "" {
					desc = s
				}
			}
			testPath := p.resolvePathParams(path)
			endpoints = append(endpoints, apiEndpoint{
				Method:      upperMethod,
				Path:        testPath,
				Description: desc,
			})
		}
	}
	return endpoints
}

func (p *AutoswaggerPlugin) resolvePathParams(path string) string {
	paramRe := regexp.MustCompile(`\{(\w+)\}`)
	return paramRe.ReplaceAllStringFunc(path, func(match string) string {
		name := strings.Trim(match, "{}")
		switch strings.ToLower(name) {
		case "id", "uid", "userid", "user_id", "accountid":
			return "1"
		case "name", "username", "user_name":
			return "admin"
		case "slug", "key", "code":
			return "test"
		case "page", "pagenum", "pageno":
			return "1"
		case "size", "pagesize", "limit":
			return "10"
		case "version", "ver":
			return "v1"
		default:
			return "1"
		}
	})
}

func (p *AutoswaggerPlugin) getCommonEndpoints() []apiEndpoint {
	return []apiEndpoint{
		{Method: "GET", Path: "/api/v1/users"},
		{Method: "GET", Path: "/api/v1/admin"},
		{Method: "GET", Path: "/api/v1/config"},
		{Method: "GET", Path: "/api/v1/settings"},
		{Method: "GET", Path: "/api/v1/metrics"},
		{Method: "GET", Path: "/api/v1/logs"},
		{Method: "GET", Path: "/api/v1/tokens"},
		{Method: "GET", Path: "/api/v1/keys"},
		{Method: "GET", Path: "/api/v1/secrets"},
		{Method: "GET", Path: "/api/users"},
		{Method: "GET", Path: "/api/admin"},
		{Method: "GET", Path: "/api/config"},
		{Method: "GET", Path: "/api/settings"},
		{Method: "GET", Path: "/api/metrics"},
		{Method: "GET", Path: "/admin"},
		{Method: "GET", Path: "/admin/config"},
		{Method: "GET", Path: "/admin/users"},
		{Method: "GET", Path: "/config"},
		{Method: "GET", Path: "/metrics"},
		{Method: "GET", Path: "/debug/pprof"},
		{Method: "GET", Path: "/debug/vars"},
		{Method: "GET", Path: "/health"},
		{Method: "GET", Path: "/status"},
		{Method: "GET", Path: "/env"},
		{Method: "GET", Path: "/info"},
		{Method: "GET", Path: "/version"},
		{Method: "GET", Path: "/actuator"},
		{Method: "GET", Path: "/actuator/env"},
		{Method: "GET", Path: "/actuator/health"},
		{Method: "GET", Path: "/actuator/configprops"},
	}
}

func (p *AutoswaggerPlugin) testEndpoint(ctx context.Context, baseURL string, ep apiEndpoint) []Finding {
	url := baseURL + ep.Path

	req, err := http.NewRequestWithContext(ctx, ep.Method, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "AI-SEC-CHECK/1.0")
	req.Header.Set("Accept", "application/json, */*")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return nil
	}

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return nil
	}

	var findings []Finding
	bodyStr := string(body)

	if resp.StatusCode == 200 {
		if p.isErrorResponse(bodyStr) {
			return nil
		}

		keyFindings := p.detectKeyLeaks(bodyStr, ep)
		findings = append(findings, keyFindings...)

		piiFindings := p.detectPII(bodyStr, ep)
		findings = append(findings, piiFindings...)

		bodyPreview := p.extractBodyPreview(bodyStr, 10)

		if len(keyFindings) == 0 && len(piiFindings) == 0 {
			if p.isSensitiveEndpoint(ep) {
				findings = append(findings, Finding{
					Severity:    SeverityMedium,
					Title:       fmt.Sprintf("%s %s - Unauthenticated access to sensitive endpoint", ep.Method, ep.Path),
					Description: fmt.Sprintf("Endpoint %s %s returned 200 OK without authentication. This endpoint may expose sensitive functionality.", ep.Method, ep.Path),
					RuleID:      "AUTOSWAGGER-UNAUTH",
					Evidence:    fmt.Sprintf("status=200, content_length=%d\n--- Response Preview ---\n%s", len(body), bodyPreview),
					Remediation: "Add authentication and authorization checks to this endpoint. Ensure unauthenticated access is intentional.",
					Source:      "autoswagger",
				})
			} else if len(body) > 10000 {
				findings = append(findings, Finding{
					Severity:    SeverityLow,
					Title:       fmt.Sprintf("%s %s - Excessive data exposure", ep.Method, ep.Path),
					Description: fmt.Sprintf("Endpoint %s %s returned a large response (%d bytes) without authentication. This may expose excessive data.", ep.Method, ep.Path, len(body)),
					RuleID:      "AUTOSWAGGER-DATA-EXPOSURE",
					Evidence:    fmt.Sprintf("status=200, content_length=%d\n--- Response Preview ---\n%s", len(body), bodyPreview),
					Remediation: "Implement pagination, field filtering, or response size limits to prevent excessive data exposure.",
					Source:      "autoswagger",
				})
			}
		}
	} else if resp.StatusCode >= 500 {
		if p.isErrorResponse(bodyStr) || p.isStandardErrorPage(bodyStr) {
			return nil
		}
		bodyPreview := p.extractBodyPreview(bodyStr, 5)
		findings = append(findings, Finding{
			Severity:    SeverityLow,
			Title:       fmt.Sprintf("%s %s - Server error exposed", ep.Method, ep.Path),
			Description: fmt.Sprintf("Endpoint %s %s returned %d error without authentication. Server errors may leak internal information.", ep.Method, ep.Path, resp.StatusCode),
			RuleID:      "AUTOSWAGGER-SERVER-ERROR",
			Evidence:    fmt.Sprintf("status=%d\n--- Response Preview ---\n%s", resp.StatusCode, bodyPreview),
			Remediation: "Implement proper error handling that does not expose internal server details.",
			Source:      "autoswagger",
		})
	}

	return findings
}

func (p *AutoswaggerPlugin) isErrorResponse(body string) bool {
	var parsed map[string]any
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		return false
	}

	if success, ok := parsed["success"]; ok {
		if b, ok := success.(bool); ok && !b {
			return true
		}
	}

	if code, ok := parsed["code"]; ok {
		switch v := code.(type) {
		case float64:
			if v >= 400 {
				return true
			}
		case string:
			if strings.Contains(strings.ToLower(v), "error") || strings.Contains(strings.ToLower(v), "fail") {
				return true
			}
		}
	}

	if status, ok := parsed["status"]; ok {
		switch v := status.(type) {
		case float64:
			if v >= 400 {
				return true
			}
		case string:
			s := strings.ToLower(v)
			if strings.Contains(s, "error") || strings.Contains(s, "fail") {
				return true
			}
		}
	}

	if msg, ok := parsed["message"]; ok {
		if s, ok := msg.(string); ok {
			lower := strings.ToLower(s)
			errorKeywords := []string{
				"服务器异常", "服务器错误", "内部错误", "系统异常", "系统错误",
				"internal server error", "server error", "service unavailable",
				"bad gateway", "gateway timeout", "请求失败", "接口异常",
				"未找到", "not found", "不存在", "参数错误", "invalid",
				"unauthorized", "forbidden", "access denied",
			}
			for _, kw := range errorKeywords {
				if strings.Contains(lower, kw) {
					return true
				}
			}
		}
	}

	if errMsg, ok := parsed["error"]; ok {
		switch v := errMsg.(type) {
		case string:
			if v != "" {
				return true
			}
		case map[string]any:
			return true
		}
	}

	if msg, ok := parsed["msg"]; ok {
		if s, ok := msg.(string); ok {
			lower := strings.ToLower(s)
			errorKeywords := []string{
				"服务器异常", "服务器错误", "内部错误", "系统异常", "系统错误",
				"internal server error", "server error", "请求失败", "接口异常",
				"未找到", "not found", "不存在", "参数错误",
			}
			for _, kw := range errorKeywords {
				if strings.Contains(lower, kw) {
					return true
				}
			}
		}
	}

	return false
}

func (p *AutoswaggerPlugin) isStandardErrorPage(body string) bool {
	if !strings.Contains(body, "<html") && !strings.Contains(body, "<HTML") {
		return false
	}

	lower := strings.ToLower(body)
	standardPatterns := []string{
		"<title>502 bad gateway</title>",
		"<title>500 internal server error</title>",
		"<title>503 service unavailable</title>",
		"<title>504 gateway timeout</title>",
		"<title>400 bad request</title>",
		"<title>404 not found</title>",
		"<title>403 forbidden</title>",
		"<center><h1>502 bad gateway</h1></center>",
		"<center><h1>500 internal server error</h1></center>",
		"<center><h1>503 service temporarily unavailable</h1></center>",
		"<center><h1>504 gateway time-out</h1></center>",
		"nginx", "apache", "tomcat",
	}
	for _, pat := range standardPatterns {
		if strings.Contains(lower, pat) {
			return true
		}
	}

	return false
}

func (p *AutoswaggerPlugin) detectKeyLeaks(body string, ep apiEndpoint) []Finding {
	var findings []Finding
	for name, pattern := range p.apiKeyPatterns {
		matches := pattern.FindAllStringIndex(body, -1)
		if len(matches) == 0 {
			continue
		}
		var evidenceParts []string
		for _, loc := range matches {
			matched := body[loc[0]:loc[1]]
			lineNum := strings.Count(body[:loc[0]], "\n") + 1
			lineStart := strings.LastIndex(body[:loc[0]], "\n") + 1
			lineEnd := strings.Index(body[loc[0]:], "\n")
			if lineEnd == -1 {
				lineEnd = len(body) - loc[0]
			}
			lineContent := strings.TrimSpace(body[lineStart : loc[0]+lineEnd])
			if len(lineContent) > 200 {
				lineContent = lineContent[:200] + "..."
			}
			evidenceParts = append(evidenceParts, fmt.Sprintf("L%d: %s => %s", lineNum, lineContent, matched))
		}
		if len(evidenceParts) > 5 {
			evidenceParts = evidenceParts[:5]
			evidenceParts = append(evidenceParts, fmt.Sprintf("... and %d more", len(matches)-5))
		}
		findings = append(findings, Finding{
			Severity:    SeverityCritical,
			Title:       fmt.Sprintf("%s %s - %s leak detected", ep.Method, ep.Path, name),
			Description: fmt.Sprintf("Endpoint %s %s exposed %d %s(s) in the response body. This is a critical security issue.", ep.Method, ep.Path, len(matches), name),
			RuleID:      "AUTOSWAGGER-KEY-LEAK",
			Evidence:    strings.Join(evidenceParts, "\n"),
			Remediation: "Remove or rotate exposed keys/secrets immediately. Implement proper access controls and never include credentials in API responses.",
			Source:      "autoswagger",
		})
	}
	return findings
}

func (p *AutoswaggerPlugin) detectPII(body string, ep apiEndpoint) []Finding {
	var findings []Finding
	var evidenceParts []string
	var detectedTypes []string

	for name, pattern := range p.piiPatterns {
		matches := pattern.FindAllStringIndex(body, -1)
		if len(matches) == 0 {
			continue
		}
		detectedTypes = append(detectedTypes, fmt.Sprintf("%s(%d)", name, len(matches)))
		for _, loc := range matches {
			matched := body[loc[0]:loc[1]]
			lineNum := strings.Count(body[:loc[0]], "\n") + 1
			lineStart := strings.LastIndex(body[:loc[0]], "\n") + 1
			lineEnd := strings.Index(body[loc[0]:], "\n")
			if lineEnd == -1 {
				lineEnd = len(body) - loc[0]
			}
			lineContent := strings.TrimSpace(body[lineStart : loc[0]+lineEnd])
			if len(lineContent) > 200 {
				lineContent = lineContent[:200] + "..."
			}
			evidenceParts = append(evidenceParts, fmt.Sprintf("[%s] L%d: %s => %s", name, lineNum, lineContent, matched))
		}
	}

	if len(detectedTypes) > 0 {
		if len(evidenceParts) > 10 {
			evidenceParts = evidenceParts[:10]
			evidenceParts = append(evidenceParts, "... (truncated)")
		}
		findings = append(findings, Finding{
			Severity:    SeverityHigh,
			Title:       fmt.Sprintf("%s %s - PII data exposure", ep.Method, ep.Path),
			Description: fmt.Sprintf("Endpoint %s %s exposed PII data in response: %s", ep.Method, ep.Path, strings.Join(detectedTypes, ", ")),
			RuleID:      "AUTOSWAGGER-PII-LEAK",
			Evidence:    strings.Join(evidenceParts, "\n"),
			Remediation: "Implement data masking or redaction for PII fields in API responses. Add authentication and authorization checks.",
			Source:      "autoswagger",
		})
	}

	return findings
}

func (p *AutoswaggerPlugin) isSensitiveEndpoint(ep apiEndpoint) bool {
	pathLower := strings.ToLower(ep.Path)
	sensitiveKeywords := []string{
		"admin", "config", "setting", "user", "token", "key", "secret",
		"password", "credential", "private", "internal", "debug",
		"pprof", "vars", "env", "actuator", "log", "audit",
	}
	for _, kw := range sensitiveKeywords {
		if strings.Contains(pathLower, kw) {
			return true
		}
	}
	return false
}

func (p *AutoswaggerPlugin) extractBodyPreview(body string, maxLines int) string {
	lines := strings.Split(body, "\n")
	if len(lines) > maxLines {
		lines = lines[:maxLines]
	}
	var preview []string
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if len(trimmed) > 200 {
			trimmed = trimmed[:200] + "..."
		}
		preview = append(preview, fmt.Sprintf("L%d: %s", i+1, trimmed))
	}
	return strings.Join(preview, "\n")
}

func (p *AutoswaggerPlugin) IsAvailable() bool {
	return p.client != nil
}

func (p *AutoswaggerPlugin) ValidateTarget(target ScanTarget) error {
	if target.Type != TargetTypeURL && target.Type != TargetTypeAPI {
		return fmt.Errorf("unsupported target type: %s, expected url/api", target.Type)
	}
	return nil
}
