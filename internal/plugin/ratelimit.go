package plugin

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type RatelimitPlugin struct {
	config PluginConfig
	client *http.Client
}

func NewRatelimitPlugin() *RatelimitPlugin {
	return &RatelimitPlugin{}
}

func (p *RatelimitPlugin) Name() string {
	return "ratelimit"
}

func (p *RatelimitPlugin) Category() string {
	return CategoryRateLimit
}

func (p *RatelimitPlugin) Description() string {
	return "Rate limiting / circuit breaker verification (built-in Go load tester)"
}

func (p *RatelimitPlugin) Init(config PluginConfig) error {
	p.config = config
	p.client = &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:        500,
			MaxIdleConnsPerHost: 500,
			IdleConnTimeout:     5 * time.Second,
			DisableKeepAlives:   false,
		},
	}
	return nil
}

type loadTestConfig struct {
	Duration       int
	MinThreads     int
	MaxThreads     int
	RampUp         int
	ThreadsLimit   int
	Method         string
	Path           string
	Headers        map[string]string
	Body           string
	Thresholds     map[string]int
}

type requestResult struct {
	StatusCode int
	Duration   time.Duration
	Error      error
}

func (p *RatelimitPlugin) Scan(ctx context.Context, target ScanTarget) (*ScanResult, error) {
	result := &ScanResult{
		PluginName: p.Name(),
		Category:   p.Category(),
		Target:     target.Value,
		Status:     StatusCompleted,
		Findings:   []Finding{},
	}

	baseURL := strings.TrimRight(target.Value, "/")
	if !strings.HasPrefix(baseURL, "http") {
		baseURL = "http://" + baseURL
	}

	ltConfig := p.parseConfig(target)

	var totalRequests int64
	var successRequests int64
	var failedRequests int64
	var statusCodes sync.Map
	var totalDuration int64
	var results []requestResult
	var mu sync.Mutex

	duration := time.Duration(ltConfig.Duration) * time.Second
	deadline := time.Now().Add(duration)
	maxDeadline := time.Now().Add(5 * time.Minute)
	if deadline.After(maxDeadline) {
		deadline = maxDeadline
	}

	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	startTime := time.Now()

	ReportProgress(ctx, 0, ltConfig.Duration, fmt.Sprintf("Starting load test: %d→%d threads, %ds duration, %ds ramp-up...",
		ltConfig.MinThreads, ltConfig.MaxThreads, ltConfig.Duration, ltConfig.RampUp))

	var wg sync.WaitGroup

	totalRequestsLimit := ltConfig.ThreadsLimit
	if totalRequestsLimit <= 0 {
		totalRequestsLimit = 1000000
	}

	sem := make(chan struct{}, ltConfig.MaxThreads)

	ReportProgress(ctx, 0, totalRequestsLimit, fmt.Sprintf("Starting load test: %d max threads, %d total requests limit, %ds duration...",
		ltConfig.MaxThreads, totalRequestsLimit, ltConfig.Duration))

	for i := 0; i < totalRequestsLimit; i++ {
		select {
		case <-ctx.Done():
			break
		default:
		}

		if time.Now().After(deadline) {
			break
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(taskID int) {
			defer wg.Done()
			defer func() { <-sem }()

			atomic.AddInt64(&totalRequests, 1)

			reqStart := time.Now()
			statusCode, err := p.sendRequest(ctx, baseURL, ltConfig)
			reqDuration := time.Since(reqStart)

			if err != nil {
				atomic.AddInt64(&failedRequests, 1)
			} else {
				atomic.AddInt64(&successRequests, 1)
				count, _ := statusCodes.LoadOrStore(statusCode, new(int64))
				atomic.AddInt64(count.(*int64), 1)
			}
			atomic.AddInt64(&totalDuration, int64(reqDuration))

			newTotal := atomic.LoadInt64(&totalRequests)
			if newTotal%10 == 0 {
				elapsed := time.Since(startTime)
				rps := float64(newTotal) / elapsed.Seconds()
				ReportProgress(ctx, int(newTotal), totalRequestsLimit,
					fmt.Sprintf("Load testing: %d requests (%.0f req/s)", newTotal, rps))
			}

			mu.Lock()
			results = append(results, requestResult{
				StatusCode: statusCode,
				Duration:   reqDuration,
				Error:      err,
			})
			mu.Unlock()
		}(i)
	}

	wg.Wait()
	elapsed := time.Since(startTime)

	findings := p.analyzeResults(totalRequests, successRequests, failedRequests, &statusCodes, totalDuration, ltConfig)

	var rawParts []string
	rawParts = append(rawParts, fmt.Sprintf("Load test: %d→%d threads, %ds duration, %ds ramp-up",
		ltConfig.MinThreads, ltConfig.MaxThreads, ltConfig.Duration, ltConfig.RampUp))
	rawParts = append(rawParts, fmt.Sprintf("Total requests: %d (success: %d, failed: %d)", totalRequests, successRequests, failedRequests))
	rawParts = append(rawParts, fmt.Sprintf("Elapsed: %.2fs", elapsed.Seconds()))

	statusCodes.Range(func(key, value interface{}) bool {
		code := key.(int)
		count := atomic.LoadInt64(value.(*int64))
		pct := float64(count) / float64(successRequests) * 100
		rawParts = append(rawParts, fmt.Sprintf("  Status %d: %d (%.1f%%)", code, count, pct))
		return true
	})

	if totalRequests > 0 {
		avgMs := float64(totalDuration) / float64(totalRequests) / float64(time.Millisecond)
		rawParts = append(rawParts, fmt.Sprintf("Avg response time: %.1fms", avgMs))
		rps := float64(totalRequests) / elapsed.Seconds()
		rawParts = append(rawParts, fmt.Sprintf("Requests/sec: %.1f", rps))
	}

	result.Findings = findings
	result.RawOutput = strings.Join(rawParts, "\n")

	if totalRequests == 0 {
		result.Summary = "Rate limit test: no requests completed (target unreachable)"
	} else {
		result.Summary = fmt.Sprintf("Rate limit test: %d request(s) in %.1fs (%.0f req/s), %d finding(s)",
			totalRequests, elapsed.Seconds(), float64(totalRequests)/elapsed.Seconds(), len(findings))
	}

	return result, nil
}

func (p *RatelimitPlugin) parseConfig(target ScanTarget) loadTestConfig {
	lt := loadTestConfig{
		Duration:     30,
		MinThreads:   10,
		MaxThreads:   200,
		RampUp:       10,
		ThreadsLimit: 0,
		Method:       "GET",
		Body:         "{}",
	}

	if v, ok := target.Metadata["duration"]; ok {
		if n, err := parseInt(v); err == nil && n > 0 {
			lt.Duration = n
		}
	}
	if v, ok := target.Metadata["min_threads"]; ok {
		if n, err := parseInt(v); err == nil && n > 0 {
			lt.MinThreads = n
		}
	}
	if v, ok := target.Metadata["max_threads"]; ok {
		if n, err := parseInt(v); err == nil && n > 0 {
			lt.MaxThreads = n
		}
	}
	if v, ok := target.Metadata["threads"]; ok {
		if n, err := parseInt(v); err == nil && n > 0 {
			lt.MaxThreads = n
			if lt.MinThreads > lt.MaxThreads {
				lt.MinThreads = lt.MaxThreads
			}
		}
	}
	if v, ok := target.Metadata["ramp_up"]; ok {
		if n, err := parseInt(v); err == nil && n > 0 {
			lt.RampUp = n
		}
	}
	if v, ok := target.Metadata["threads_limit"]; ok {
		if n, err := parseInt(v); err == nil && n >= 0 {
			lt.ThreadsLimit = n
		}
	}
	if v, ok := target.Metadata["method"]; ok && v != "" {
		lt.Method = strings.ToUpper(v)
	}
	if v, ok := target.Metadata["path"]; ok && v != "" {
		lt.Path = v
	}
	if v, ok := target.Metadata["headers"]; ok && v != "" {
		lt.Headers = parseHeaders(v)
	}
	if v, ok := target.Metadata["body"]; ok && v != "" {
		lt.Body = v
	}

	if lt.Duration > 300 {
		lt.Duration = 300
	}
	if lt.ThreadsLimit > 0 && lt.MaxThreads > lt.ThreadsLimit {
		lt.MaxThreads = lt.ThreadsLimit
	}
	if lt.ThreadsLimit == 0 && lt.MaxThreads > 500 {
		lt.MaxThreads = 500
	}
	if lt.MinThreads > lt.MaxThreads {
		lt.MinThreads = lt.MaxThreads
	}
	if lt.MinThreads < 1 {
		lt.MinThreads = 1
	}

	return lt
}

func parseInt(s string) (int, error) {
	n := 0
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		} else {
			return 0, fmt.Errorf("invalid integer")
		}
	}
	return n, nil
}

func parseHeaders(s string) map[string]string {
	headers := make(map[string]string)
	if s == "" {
		return headers
	}
	pairs := strings.Split(s, ";")
	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		colonIdx := strings.Index(pair, ":")
		if colonIdx > 0 {
			key := strings.TrimSpace(pair[:colonIdx])
			value := strings.TrimSpace(pair[colonIdx+1:])
			if key != "" {
				headers[key] = value
			}
		}
	}
	return headers
}

func (p *RatelimitPlugin) sendRequest(ctx context.Context, baseURL string, lt loadTestConfig) (int, error) {
	url := baseURL
	if lt.Path != "" {
		url = baseURL + lt.Path
	}

	var bodyReader io.Reader
	if lt.Body != "" && (lt.Method == "POST" || lt.Method == "PUT" || lt.Method == "PATCH") {
		bodyReader = strings.NewReader(lt.Body)
	}

	req, err := http.NewRequestWithContext(ctx, lt.Method, url, bodyReader)
	if err != nil {
		return 0, err
	}

	req.Header.Set("User-Agent", "AI-SEC-CHECK-LoadTest/1.0")
	req.Header.Set("Accept", "*/*")
	req.Close = false

	if lt.Body != "" && (lt.Method == "POST" || lt.Method == "PUT" || lt.Method == "PATCH") {
		req.Header.Set("Content-Type", "application/json")
	}

	for k, v := range lt.Headers {
		req.Header.Set(k, v)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return 0, err
	}

	_, _ = io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	resp.Body.Close()

	return resp.StatusCode, nil
}

func (p *RatelimitPlugin) analyzeResults(
	totalRequests int64,
	successRequests int64,
	failedRequests int64,
	statusCodes *sync.Map,
	totalDuration int64,
	lt loadTestConfig,
) []Finding {
	var findings []Finding

	count200 := int64(0)
	count429 := int64(0)
	count503 := int64(0)
	count5xx := int64(0)
	count4xx := int64(0)
	countOther := int64(0)

	statusCodes.Range(func(key, value interface{}) bool {
		code := key.(int)
		count := atomic.LoadInt64(value.(*int64))

		switch {
		case code == 200 || code == 201 || code == 204:
			count200 += count
		case code == 429:
			count429 += count
		case code == 503:
			count503 += count
		case code >= 500:
			count5xx += count
		case code >= 400:
			count4xx += count
		default:
			countOther += count
		}
		return true
	})

	if totalRequests == 0 {
		findings = append(findings, Finding{
			Severity:    SeverityHigh,
			Title:       "Target unreachable during load test",
			Description: "No successful requests were made during the load test. The target may be down or blocking connections.",
			RuleID:      "RL-UNREACHABLE",
			Evidence:    fmt.Sprintf("total_requests=0, errors=%d", failedRequests),
			Remediation: "Verify the target URL is correct and the service is running.",
			Source:      "ratelimit",
		})
		return findings
	}

	effectiveTotal := successRequests
	if effectiveTotal == 0 {
		effectiveTotal = totalRequests
	}

	successRate := float64(count200+countOther) / float64(effectiveTotal) * 100
	rateLimitedRate := float64(count429) / float64(effectiveTotal) * 100
	circuitBreakerRate := float64(count503) / float64(effectiveTotal) * 100
	serverErrorRate := float64(count5xx) / float64(effectiveTotal) * 100

	if count429 == 0 && count503 == 0 && count5xx == 0 {
		findings = append(findings, Finding{
			Severity:    SeverityHigh,
			Title:       "No rate limiting detected",
			Description: fmt.Sprintf("Sent %d requests with %d→%d concurrent threads over %ds. All requests returned successful responses (200/201/204: %d, %.1f%%). No rate limiting or circuit breaker protection was triggered.", totalRequests, lt.MinThreads, lt.MaxThreads, lt.Duration, count200, successRate),
			RuleID:      "RL-NO-LIMIT",
			Evidence:    fmt.Sprintf("total=%d, success=%d, failed=%d, 200=%d(%.1f%%), 429=%d, 503=%d, 5xx=%d", totalRequests, successRequests, failedRequests, count200, successRate, count429, count503, count5xx),
			Remediation: "Implement rate limiting (e.g., token bucket, sliding window) to protect against abuse. Consider adding circuit breakers for cascading failure prevention.",
			Source:      "ratelimit",
		})
	}

	if rateLimitedRate > 0 && rateLimitedRate < 10 {
		findings = append(findings, Finding{
			Severity:    SeverityMedium,
			Title:       "Weak rate limiting detected",
			Description: fmt.Sprintf("Rate limiting is present but only %.1f%% of requests were throttled (429). Under %d→%d concurrent threads, this suggests the rate limit threshold may be too high.", rateLimitedRate, lt.MinThreads, lt.MaxThreads),
			RuleID:      "RL-WEAK",
			Evidence:    fmt.Sprintf("total=%d, 429=%d(%.1f%%), 200=%d(%.1f%%)", effectiveTotal, count429, rateLimitedRate, count200, successRate),
			Remediation: "Lower the rate limit threshold and consider implementing graduated throttling (slow down before rejecting).",
			Source:      "ratelimit",
		})
	}

	if rateLimitedRate >= 10 && rateLimitedRate <= 80 {
		findings = append(findings, Finding{
			Severity:    SeverityInfo,
			Title:       "Rate limiting is active",
			Description: fmt.Sprintf("Rate limiting is working: %.1f%% of requests were throttled (429). This indicates effective rate limiting protection.", rateLimitedRate),
			RuleID:      "RL-ACTIVE",
			Evidence:    fmt.Sprintf("total=%d, 429=%d(%.1f%%), 200=%d(%.1f%%)", effectiveTotal, count429, rateLimitedRate, count200, successRate),
			Remediation: "Rate limiting is functioning. Monitor and adjust thresholds as needed.",
			Source:      "ratelimit",
		})
	}

	if rateLimitedRate > 80 {
		findings = append(findings, Finding{
			Severity:    SeverityMedium,
			Title:       "Overly aggressive rate limiting",
			Description: fmt.Sprintf("Rate limiting rejected %.1f%% of requests (429). This may be too aggressive and could impact legitimate users.", rateLimitedRate),
			RuleID:      "RL-AGGRESSIVE",
			Evidence:    fmt.Sprintf("total=%d, 429=%d(%.1f%%), 200=%d(%.1f%%)", effectiveTotal, count429, rateLimitedRate, count200, successRate),
			Remediation: "Consider increasing the rate limit threshold to allow more legitimate traffic while still protecting against abuse.",
			Source:      "ratelimit",
		})
	}

	if circuitBreakerRate > 5 {
		findings = append(findings, Finding{
			Severity:    SeverityMedium,
			Title:       "Circuit breaker triggered",
			Description: fmt.Sprintf("Circuit breaker returned 503 for %.1f%% of requests (%d total). This indicates the service is shedding load under pressure.", circuitBreakerRate, count503),
			RuleID:      "RL-CIRCUIT-BREAKER",
			Evidence:    fmt.Sprintf("total=%d, 503=%d(%.1f%%)", effectiveTotal, count503, circuitBreakerRate),
			Remediation: "Circuit breaker is functioning. Review if the trigger threshold is appropriate for your capacity.",
			Source:      "ratelimit",
		})
	}

	if serverErrorRate > 10 {
		findings = append(findings, Finding{
			Severity:    SeverityCritical,
			Title:       "Server errors under load",
			Description: fmt.Sprintf("%.1f%% of requests resulted in 5xx server errors (%d total). The service may be unstable under load.", serverErrorRate, count5xx),
			RuleID:      "RL-SERVER-ERROR",
			Evidence:    fmt.Sprintf("total=%d, 5xx=%d(%.1f%%)", effectiveTotal, count5xx, serverErrorRate),
			Remediation: "Investigate the root cause of server errors. Add proper error handling, resource limits, and graceful degradation.",
			Source:      "ratelimit",
		})
	}

	if totalRequests > 0 {
		avgMs := float64(totalDuration) / float64(totalRequests) / float64(time.Millisecond)
		if avgMs > 3000 {
			findings = append(findings, Finding{
				Severity:    SeverityMedium,
				Title:       "High average response time under load",
				Description: fmt.Sprintf("Average response time is %.0fms under %d→%d concurrent threads. This may indicate performance bottlenecks.", avgMs, lt.MinThreads, lt.MaxThreads),
				RuleID:      "RL-SLOW",
				Evidence:    fmt.Sprintf("avg_response=%.0fms, threads=%d→%d", avgMs, lt.MinThreads, lt.MaxThreads),
				Remediation: "Optimize slow endpoints, add caching, or increase server capacity. Consider implementing response time-based circuit breakers.",
				Source:      "ratelimit",
			})
		}
	}

	return findings
}

func (p *RatelimitPlugin) IsAvailable() bool {
	return p.client != nil
}

func (p *RatelimitPlugin) ValidateTarget(target ScanTarget) error {
	switch target.Type {
	case TargetTypeURL, TargetTypeAPI:
		return nil
	default:
		return fmt.Errorf("unsupported target type: %s, expected url/api", target.Type)
	}
}
