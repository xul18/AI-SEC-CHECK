package websocket

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"ai-sec-check/internal/ai"
	"ai-sec-check/internal/config"
	"ai-sec-check/internal/plugin"
	"ai-sec-check/internal/storage"

	"github.com/gin-gonic/gin"
)

type AIAPI struct {
	manager  *ai.Manager
	storage  *storage.ScanResultStore
	registry *plugin.Registry
}

func NewAIAPI(manager *ai.Manager, storage *storage.ScanResultStore, registry *plugin.Registry) *AIAPI {
	return &AIAPI{
		manager:  manager,
		storage:  storage,
		registry: registry,
	}
}

func (api *AIAPI) HandleStatus(c *gin.Context) {
	enabled := api.manager.IsAIEnabled()
	connected := false
	if enabled {
		connected = api.manager.CheckPrimaryConnection() == nil
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  0,
		"message": "ok",
		"data": gin.H{
			"enabled":   enabled,
			"available": enabled,
			"connected": connected,
			"provider":  "openai",
			"model":     api.manager.GetModelName(),
			"base_url":  api.manager.GetBaseURL(),
		},
	})
}

type AIAnalyzeRequest struct {
	ScanResultIDs []string `json:"scan_result_ids"`
	Category      string   `json:"category"`
	Limit         int      `json:"limit"`
}

func (api *AIAPI) HandleAnalyze(c *gin.Context) {
	var req AIAnalyzeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status":  1,
			"message": "invalid parameters: " + err.Error(),
		})
		return
	}

	results, err := api.collectResults(req)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status":  1,
			"message": "failed to collect results: " + err.Error(),
		})
		return
	}

	if len(results) == 0 {
		c.JSON(http.StatusOK, gin.H{
			"status":  1,
			"message": "no scan results found for analysis",
		})
		return
	}

	analysis, err := api.manager.Analyze(results)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status":  1,
			"message": "AI analysis failed: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  0,
		"message": "ok",
		"data": gin.H{
			"analysis":     analysis,
			"ai_enabled":   api.manager.IsAIEnabled(),
			"result_count": len(results),
		},
	})
}

type AIReportRequest struct {
	ScanResultIDs []string `json:"scan_result_ids"`
	Category      string   `json:"category"`
	Format        string   `json:"format"`
	Limit         int      `json:"limit"`
}

func (api *AIAPI) HandleGenerateReport(c *gin.Context) {
	var req AIReportRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status":  1,
			"message": "invalid parameters: " + err.Error(),
		})
		return
	}

	if req.Format == "" {
		req.Format = "markdown"
	}

	results, err := api.collectResults(AIAnalyzeRequest{
		ScanResultIDs: req.ScanResultIDs,
		Category:      req.Category,
		Limit:         req.Limit,
	})
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status":  1,
			"message": "failed to collect results: " + err.Error(),
		})
		return
	}

	if len(results) == 0 {
		c.JSON(http.StatusOK, gin.H{
			"status":  1,
			"message": "no scan results found",
		})
		return
	}

	report, err := api.manager.GenerateReport(results, req.Format)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status":  1,
			"message": "report generation failed: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  0,
		"message": "ok",
		"data": gin.H{
			"report":     report,
			"format":     req.Format,
			"ai_enabled": api.manager.IsAIEnabled(),
		},
	})
}

type AISuggestFixRequest struct {
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
	RuleID      string `json:"rule_id"`
	Evidence    string `json:"evidence"`
	Source      string `json:"source"`
}

func (api *AIAPI) HandleSuggestFix(c *gin.Context) {
	var req AISuggestFixRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status":  1,
			"message": "invalid parameters: " + err.Error(),
		})
		return
	}

	finding := plugin.Finding{
		Severity:    req.Severity,
		Title:       req.Title,
		Description: req.Description,
		RuleID:      req.RuleID,
		Evidence:    req.Evidence,
		Source:      req.Source,
	}

	suggestion, err := api.manager.SuggestFix(finding)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status":  1,
			"message": "fix suggestion failed: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  0,
		"message": "ok",
		"data": gin.H{
			"suggestion": suggestion,
			"ai_enabled": api.manager.IsAIEnabled(),
		},
	})
}

type AIChatRequest struct {
	Question    string `json:"question" binding:"required"`
	Context     string `json:"context"`
	FileContent string `json:"file_content"`
	FileName    string `json:"file_name"`
}

func (api *AIAPI) HandleChat(c *gin.Context) {
	var req AIChatRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status":  1,
			"message": "invalid parameters: " + err.Error(),
		})
		return
	}

	intent := ai.ParseScanIntent(req.Question)
	if intent.Detected && api.registry != nil {
		var targetValue string
		if req.FileContent != "" && (strings.Contains(strings.ToLower(req.Question), "敏感词") || 
			strings.Contains(strings.ToLower(req.Question), "sensitive") ||
			intent.PluginName == "sensitive_word") {
			if strings.HasSuffix(strings.ToLower(req.FileName), ".docx") && strings.HasPrefix(req.FileContent, "data:") {
				base64Data := strings.SplitN(req.FileContent, ",", 2)[1]
				decoded, err := base64.StdEncoding.DecodeString(base64Data)
				if err != nil {
					c.JSON(http.StatusOK, gin.H{
						"status":  1,
						"message": "failed to decode docx file: " + err.Error(),
					})
					return
				}
				docxText, docxErr := plugin.ExtractTextFromDocx(decoded)
				if docxErr != nil {
					c.JSON(http.StatusOK, gin.H{
						"status":  1,
						"message": "failed to parse docx file: " + docxErr.Error(),
					})
					return
				}
				targetValue = docxText
			} else {
				targetValue = req.FileContent
			}
		} else {
			targetValue = intent.TargetValue
		}

		scanResult, scanErr := api.executeScanWithTarget(intent, targetValue)
		if scanErr != nil {
			answer, _ := api.manager.Chat(req.Question, req.Context)
			c.JSON(http.StatusOK, gin.H{
				"status":  0,
				"message": "ok",
				"data": gin.H{
					"answer":     fmt.Sprintf("扫描启动失败: %s\n\n%s", scanErr.Error(), answer),
					"ai_enabled": api.manager.IsAIEnabled(),
				},
			})
			return
		}

		var aiAnalysis string
		if api.manager.IsAIEnabled() {
			analysis, err := api.manager.Analyze([]*plugin.ScanResult{scanResult})
			if err == nil {
				aiAnalysis = analysis
			}
		}

		c.JSON(http.StatusOK, gin.H{
			"status":  0,
			"message": "ok",
			"data": gin.H{
				"answer":     formatScanResultMessage(intent, scanResult, aiAnalysis),
				"ai_enabled": api.manager.IsAIEnabled(),
				"scan_result": gin.H{
					"id":         scanResult.ID,
					"plugin":     scanResult.PluginName,
					"target":     scanResult.Target,
					"status":     scanResult.Status,
					"summary":    scanResult.Summary,
					"findings":   scanResult.Findings,
					"duration":   scanResult.Duration,
					"scan_time":  scanResult.ScanTime,
					"raw_output": scanResult.RawOutput,
				},
				"scan_intent": intent,
			},
		})
		return
	}

	answer, err := api.manager.Chat(req.Question, req.Context)
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "AI service error") {
			c.JSON(http.StatusOK, gin.H{
				"status":  0,
				"message": "ok",
				"data": gin.H{
					"answer":     fmt.Sprintf("AI 服务连接失败，请检查配置是否正确。\n\n错误详情: %s", strings.TrimPrefix(errMsg, "AI service error: ")),
					"ai_enabled": api.manager.IsAIEnabled(),
				},
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"status":  1,
			"message": "chat failed: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  0,
		"message": "ok",
		"data": gin.H{
			"answer":     answer,
			"ai_enabled": api.manager.IsAIEnabled(),
		},
	})
}

func (api *AIAPI) executeScan(intent ai.ScanIntent) (*plugin.ScanResult, error) {
	return api.executeScanWithTarget(intent, intent.TargetValue)
}

func (api *AIAPI) executeScanWithTarget(intent ai.ScanIntent, targetValue string) (*plugin.ScanResult, error) {
	p, ok := api.registry.Get(intent.PluginName)
	if !ok {
		return nil, fmt.Errorf("plugin %s not found", intent.PluginName)
	}

	if !p.IsAvailable() {
		return nil, fmt.Errorf("plugin %s is not available", intent.PluginName)
	}

	scanTarget := plugin.ScanTarget{
		Type:  intent.TargetType,
		Value: targetValue,
	}

	if err := p.ValidateTarget(scanTarget); err != nil {
		return nil, fmt.Errorf("invalid target: %w", err)
	}

	cfg := plugin.PluginConfig{}
	if err := p.Init(cfg); err != nil {
		return nil, fmt.Errorf("plugin init failed: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	result, err := p.Scan(ctx, scanTarget)
	if err != nil {
		return nil, fmt.Errorf("scan failed: %w", err)
	}

	if api.storage != nil && result != nil {
		_ = api.storage.Save(result)
	}

	return result, nil
}

func formatScanResultMessage(intent ai.ScanIntent, result *plugin.ScanResult, aiAnalysis string) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("🔍 已自动执行 **%s** 扫描\n", intent.PluginName))
	sb.WriteString(fmt.Sprintf("🎯 目标: `%s`\n", intent.TargetValue))
	sb.WriteString(fmt.Sprintf("📊 状态: %s | 耗时: %.1fs\n\n", result.Status, result.Duration))

	if result.Summary != "" {
		sb.WriteString("## 扫描摘要\n")
		sb.WriteString(result.Summary + "\n\n")
	}

	if len(result.Findings) > 0 {
		sb.WriteString(fmt.Sprintf("## 发现 %d 个安全问题\n\n", len(result.Findings)))
		for i, f := range result.Findings {
			sb.WriteString(fmt.Sprintf("### %d. [%s] %s\n", i+1, strings.ToUpper(f.Severity), f.Title))
			if f.Description != "" {
				sb.WriteString(f.Description + "\n")
			}
			if f.Evidence != "" {
				sb.WriteString(fmt.Sprintf("**证据:**\n```\n%s\n```\n", f.Evidence))
			}
			if f.Remediation != "" {
				sb.WriteString(fmt.Sprintf("**修复建议:** %s\n", f.Remediation))
			}
			sb.WriteString("\n")
		}
	} else {
		sb.WriteString("✅ 未发现安全问题\n")
	}

	if aiAnalysis != "" {
		sb.WriteString("\n## AI 分析\n")
		sb.WriteString(aiAnalysis + "\n")
	}

	return sb.String()
}

type AIConfigUpdateRequest struct {
	Enabled bool   `json:"enabled"`
	BaseURL string `json:"base_url"`
	APIKey  string `json:"api_key"`
	Model   string `json:"model"`
}

func (api *AIAPI) HandleUpdateConfig(c *gin.Context) {
	var req AIConfigUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status":  1,
			"message": "invalid parameters: " + err.Error(),
		})
		return
	}

	aiCfg := ai.AIConfig{
		Enabled:  req.Enabled,
		Provider: "openai",
		BaseURL:  req.BaseURL,
		APIKey:   req.APIKey,
		Model:    req.Model,
	}

	api.manager.UpdateConfig(aiCfg)

	if err := config.SaveAIConfig(aiCfg); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status":  1,
			"message": "config updated in memory but failed to save: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  0,
		"message": "AI configuration updated and saved",
		"data": gin.H{
			"enabled":   api.manager.IsAIEnabled(),
			"available": api.manager.IsAvailable(),
		},
	})
}

func (api *AIAPI) collectResults(req AIAnalyzeRequest) ([]*plugin.ScanResult, error) {
	if api.storage == nil {
		return nil, nil
	}

	if len(req.ScanResultIDs) > 0 {
		results := make([]*plugin.ScanResult, 0, len(req.ScanResultIDs))
		for _, id := range req.ScanResultIDs {
			r, err := api.storage.Get(id)
			if err != nil {
				continue
			}
			results = append(results, r)
		}
		return results, nil
	}

	limit := req.Limit
	if limit <= 0 {
		limit = 20
	}

	if req.Category != "" {
		return api.storage.ListByCategory(req.Category, limit)
	}

	return api.storage.List(limit)
}
