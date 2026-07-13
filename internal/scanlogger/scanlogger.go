package scanlogger

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	logger *ScanLogger
	mu     sync.Mutex
)

type ScanLogger struct {
	logDir string
}

type ScanLogEntry struct {
	Timestamp    string                 `json:"timestamp"`
	PluginName   string                 `json:"plugin_name"`
	Target       string                 `json:"target"`
	Category     string                 `json:"category"`
	Level        string                 `json:"level"`
	Message      string                 `json:"message"`
	Prompt       string                 `json:"prompt,omitempty"`
	Response     string                 `json:"response,omitempty"`
	StatusCode   int                    `json:"status_code,omitempty"`
	Evidence     string                 `json:"evidence,omitempty"`
	RuleID       string                 `json:"rule_id,omitempty"`
	Severity     string                 `json:"severity,omitempty"`
	Duration     float64                `json:"duration,omitempty"`
	Extra        map[string]interface{} `json:"extra,omitempty"`
}

func Init(logDir string) {
	mu.Lock()
	defer mu.Unlock()

	if err := os.MkdirAll(logDir, 0755); err != nil {
		fmt.Printf("Failed to create log directory: %v\n", err)
		return
	}

	logger = &ScanLogger{
		logDir: logDir,
	}
}

func GetLogger() *ScanLogger {
	mu.Lock()
	defer mu.Unlock()
	return logger
}

func (sl *ScanLogger) log(entry ScanLogEntry) {
	if sl == nil {
		return
	}

	entry.Timestamp = time.Now().Format("2006-01-02 15:04:05.000")

	logFileName := filepath.Join(sl.logDir, fmt.Sprintf("scan_%s.log", time.Now().Format("2006-01-02")))

	file, err := os.OpenFile(logFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Failed to open log file: %v\n", err)
		return
	}
	defer file.Close()

	data, err := json.Marshal(entry)
	if err != nil {
		fmt.Printf("Failed to marshal log entry: %v\n", err)
		return
	}

	if _, err := file.WriteString(string(data) + "\n"); err != nil {
		fmt.Printf("Failed to write log entry: %v\n", err)
		return
	}
}

func (sl *ScanLogger) Info(pluginName, target, message string) {
	sl.log(ScanLogEntry{
		PluginName: pluginName,
		Target:     target,
		Level:      "INFO",
		Message:    message,
	})
}

func (sl *ScanLogger) Warn(pluginName, target, message string) {
	sl.log(ScanLogEntry{
		PluginName: pluginName,
		Target:     target,
		Level:      "WARN",
		Message:    message,
	})
}

func (sl *ScanLogger) Error(pluginName, target, message string) {
	sl.log(ScanLogEntry{
		PluginName: pluginName,
		Target:     target,
		Level:      "ERROR",
		Message:    message,
	})
}

func (sl *ScanLogger) Debug(pluginName, target, message string) {
	sl.log(ScanLogEntry{
		PluginName: pluginName,
		Target:     target,
		Level:      "DEBUG",
		Message:    message,
	})
}

func (sl *ScanLogger) ScanStart(pluginName, target, category string) {
	sl.log(ScanLogEntry{
		PluginName: pluginName,
		Target:     target,
		Category:   category,
		Level:      "INFO",
		Message:    "Scan started",
	})
}

func (sl *ScanLogger) ScanComplete(pluginName, target, category string, findings int, duration float64) {
	sl.log(ScanLogEntry{
		PluginName: pluginName,
		Target:     target,
		Category:   category,
		Level:      "INFO",
		Message:    fmt.Sprintf("Scan completed with %d findings", findings),
		Duration:   duration,
		Extra: map[string]interface{}{
			"findings_count": findings,
		},
	})
}

func (sl *ScanLogger) ProbeSent(pluginName, target, category, probeName, prompt string) {
	sl.log(ScanLogEntry{
		PluginName: pluginName,
		Target:     target,
		Category:   category,
		Level:      "DEBUG",
		Message:    fmt.Sprintf("Probe sent: %s/%s", category, probeName),
		Prompt:     prompt,
		Extra: map[string]interface{}{
			"probe_name": probeName,
		},
	})
}

func (sl *ScanLogger) ProbeResult(pluginName, target, category, probeName, prompt, response string, statusCode int, jailbroken bool, severity string) {
	sl.log(ScanLogEntry{
		PluginName: pluginName,
		Target:     target,
		Category:   category,
		Level:      "INFO",
		Message:    fmt.Sprintf("Probe result: %s/%s - %s", category, probeName, map[bool]string{true: "JAILBROKEN", false: "BLOCKED"}[jailbroken]),
		Prompt:     prompt,
		Response:   response,
		StatusCode: statusCode,
		Severity:   severity,
		Extra: map[string]interface{}{
			"probe_name":  probeName,
			"jailbroken":  jailbroken,
		},
	})
}

func (sl *ScanLogger) EndpointTest(pluginName, target, endpoint, method string, statusCode int, response string, duration float64) {
	sl.log(ScanLogEntry{
		PluginName: pluginName,
		Target:     target,
		Category:   "api",
		Level:      "DEBUG",
		Message:    fmt.Sprintf("Endpoint tested: %s %s -> %d", method, endpoint, statusCode),
		Response:   response,
		StatusCode: statusCode,
		Duration:   duration,
		Extra: map[string]interface{}{
			"endpoint": endpoint,
			"method":   method,
		},
	})
}

func (sl *ScanLogger) Finding(pluginName, target, ruleID, severity, title, description, evidence string) {
	sl.log(ScanLogEntry{
		PluginName: pluginName,
		Target:     target,
		Level:      "WARN",
		Message:    fmt.Sprintf("Finding: %s - %s", ruleID, title),
		RuleID:     ruleID,
		Severity:   severity,
		Evidence:   evidence,
		Extra: map[string]interface{}{
			"title":       title,
			"description": description,
		},
	})
}

func (sl *ScanLogger) Request(pluginName, target, method, url, body string, statusCode int, response string) {
	sl.log(ScanLogEntry{
		PluginName: pluginName,
		Target:     target,
		Level:      "DEBUG",
		Message:    fmt.Sprintf("HTTP %s %s -> %d", method, url, statusCode),
		Prompt:     body,
		Response:   response,
		StatusCode: statusCode,
		Extra: map[string]interface{}{
			"method": method,
			"url":    url,
		},
	})
}

func Info(pluginName, target, message string) {
	if logger != nil {
		logger.Info(pluginName, target, message)
	}
}

func Warn(pluginName, target, message string) {
	if logger != nil {
		logger.Warn(pluginName, target, message)
	}
}

func Error(pluginName, target, message string) {
	if logger != nil {
		logger.Error(pluginName, target, message)
	}
}

func Debug(pluginName, target, message string) {
	if logger != nil {
		logger.Debug(pluginName, target, message)
	}
}

func ScanStart(pluginName, target, category string) {
	if logger != nil {
		logger.ScanStart(pluginName, target, category)
	}
}

func ScanComplete(pluginName, target, category string, findings int, duration float64) {
	if logger != nil {
		logger.ScanComplete(pluginName, target, category, findings, duration)
	}
}

func ProbeSent(pluginName, target, category, probeName, prompt string) {
	if logger != nil {
		logger.ProbeSent(pluginName, target, category, probeName, prompt)
	}
}

func ProbeResult(pluginName, target, category, probeName, prompt, response string, statusCode int, jailbroken bool, severity string) {
	if logger != nil {
		logger.ProbeResult(pluginName, target, category, probeName, prompt, response, statusCode, jailbroken, severity)
	}
}

func EndpointTest(pluginName, target, endpoint, method string, statusCode int, response string, duration float64) {
	if logger != nil {
		logger.EndpointTest(pluginName, target, endpoint, method, statusCode, response, duration)
	}
}

func Finding(pluginName, target, ruleID, severity, title, description, evidence string) {
	if logger != nil {
		logger.Finding(pluginName, target, ruleID, severity, title, description, evidence)
	}
}

func Request(pluginName, target, method, url, body string, statusCode int, response string) {
	if logger != nil {
		logger.Request(pluginName, target, method, url, body, statusCode, response)
	}
}