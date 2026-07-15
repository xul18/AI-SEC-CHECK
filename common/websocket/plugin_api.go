package websocket

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"ai-sec-check/internal/ai"
	"ai-sec-check/internal/plugin"
	"ai-sec-check/internal/storage"

	"github.com/gin-gonic/gin"
)

type PluginAPI struct {
	registry  *plugin.Registry
	storage   *storage.ScanResultStore
	aiManager *ai.Manager
}

func NewPluginAPI(registry *plugin.Registry, storage *storage.ScanResultStore, aiManager *ai.Manager) *PluginAPI {
	return &PluginAPI{
		registry:  registry,
		storage:   storage,
		aiManager: aiManager,
	}
}

type PluginListResponse struct {
	Name        string `json:"name"`
	Category    string `json:"category"`
	Description string `json:"description"`
	Available   bool   `json:"available"`
}

func (api *PluginAPI) HandleListPlugins(c *gin.Context) {
	plugins := api.registry.List()
	response := make([]PluginListResponse, 0, len(plugins))
	for _, p := range plugins {
		response = append(response, PluginListResponse{
			Name:        p.Name(),
			Category:    p.Category(),
			Description: p.Description(),
			Available:   p.IsAvailable(),
		})
	}
	c.JSON(http.StatusOK, gin.H{
		"status":  0,
		"message": "ok",
		"data":    response,
	})
}

type scanProgress struct {
	Current int                `json:"current"`
	Total   int                `json:"total"`
	Message string             `json:"message"`
	Status  string             `json:"status"`
	Result  *plugin.ScanResult `json:"result,omitempty"`
	mu      sync.RWMutex
}

func (sp *scanProgress) update(current, total int, message string) {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	sp.Current = current
	sp.Total = total
	sp.Message = message
}

func (sp *scanProgress) snapshot() scanProgress {
	sp.mu.RLock()
	defer sp.mu.RUnlock()
	return scanProgress{
		Current: sp.Current,
		Total:   sp.Total,
		Message: sp.Message,
		Status:  sp.Status,
		Result:  sp.Result,
	}
}

type scanProgressSnapshot struct {
	Current int                `json:"current"`
	Total   int                `json:"total"`
	Message string             `json:"message"`
	Status  string             `json:"status"`
	Result  *plugin.ScanResult `json:"result,omitempty"`
}

func (sp *scanProgress) getSnapshot() scanProgressSnapshot {
	sp.mu.RLock()
	defer sp.mu.RUnlock()
	return scanProgressSnapshot{
		Current: sp.Current,
		Total:   sp.Total,
		Message: sp.Message,
		Status:  sp.Status,
		Result:  sp.Result,
	}
}

var scanProgressStore sync.Map

func generateScanID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

type PluginScanRequest struct {
	PluginName string                 `json:"plugin_name" binding:"required"`
	TargetType string                 `json:"target_type" binding:"required"`
	Target     string                 `json:"target" binding:"required"`
	FileName   string                 `json:"file_name,omitempty"`
	Metadata   map[string]string      `json:"metadata,omitempty"`
	Params     map[string]interface{} `json:"params,omitempty"`
	AIAnalyze  bool                   `json:"ai_analyze,omitempty"`
}

func (api *PluginAPI) HandlePluginScan(c *gin.Context) {
	var req PluginScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status":  1,
			"message": "invalid parameters: " + err.Error(),
			"data":    nil,
		})
		return
	}

	p, ok := api.registry.Get(req.PluginName)
	if !ok {
		c.JSON(http.StatusOK, gin.H{
			"status":  1,
			"message": "plugin not found: " + req.PluginName,
			"data":    nil,
		})
		return
	}

	if !p.IsAvailable() {
		c.JSON(http.StatusOK, gin.H{
			"status":  1,
			"message": "plugin not available: " + req.PluginName,
			"data":    nil,
		})
		return
	}

	if req.Params != nil {
		cfg := plugin.PluginConfig(req.Params)
		if err := p.Init(cfg); err != nil {
			c.JSON(http.StatusOK, gin.H{
				"status":  1,
				"message": "plugin init failed: " + err.Error(),
				"data":    nil,
			})
			return
		}
	}

	var targetValue = req.Target
	var targetType = req.TargetType
	if req.TargetType == "file" && req.FileName != "" {
		if strings.HasPrefix(req.Target, "data:") {
			ext := strings.ToLower(req.FileName[strings.LastIndex(req.FileName, "."):])
			base64Data := strings.SplitN(req.Target, ",", 2)[1]
			decoded, err := base64.StdEncoding.DecodeString(base64Data)
			if err != nil {
				c.JSON(http.StatusOK, gin.H{
					"status":  1,
					"message": "failed to decode file: " + err.Error(),
					"data":    nil,
				})
				return
			}

			switch ext {
			case ".docx", ".wps", ".docm", ".dotx", ".dotm":
				docxText, docxErr := plugin.ExtractTextFromDocx(decoded)
				if docxErr != nil {
					c.JSON(http.StatusOK, gin.H{
						"status":  1,
						"message": "failed to parse document file: " + docxErr.Error(),
						"data":    nil,
					})
					return
				}
				targetValue = docxText
			case ".pdf":
				pdfText, pdfErr := plugin.ExtractTextFromPDF(decoded)
				if pdfErr != nil {
					c.JSON(http.StatusOK, gin.H{
						"status":  1,
						"message": "failed to parse pdf file: " + pdfErr.Error(),
						"data":    nil,
					})
					return
				}
				targetValue = pdfText
			case ".xlsx", ".xlsb", ".xlsm", ".et", ".ett":
				xlsxText, xlsxErr := plugin.ExtractTextFromXlsx(decoded)
				if xlsxErr != nil {
					c.JSON(http.StatusOK, gin.H{
						"status":  1,
						"message": "failed to parse excel file: " + xlsxErr.Error(),
						"data":    nil,
					})
					return
				}
				targetValue = xlsxText
			case ".doc", ".xls":
				legacyText, legacyErr := plugin.ExtractTextFromLegacyOffice(decoded, ext)
				if legacyErr != nil {
					c.JSON(http.StatusOK, gin.H{
						"status":  1,
						"message": "failed to parse legacy office file: " + legacyErr.Error(),
						"data":    nil,
					})
					return
				}
				targetValue = legacyText
			default:
				targetValue = string(decoded)
			}
		}
		targetType = "text"
	}

	if req.Metadata == nil {
		req.Metadata = make(map[string]string)
	}
	if req.FileName != "" {
		req.Metadata["file_name"] = req.FileName
	}

	scanTarget := plugin.ScanTarget{
		Type:     targetType,
		Value:    targetValue,
		Metadata: req.Metadata,
	}

	if err := p.ValidateTarget(scanTarget); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status":  1,
			"message": "invalid target: " + err.Error(),
			"data":    nil,
		})
		return
	}

	scanID := generateScanID()
	progress := &scanProgress{Status: "running", Total: 100, Message: "Initializing scan..."}
	scanProgressStore.Store(scanID, progress)

	c.JSON(http.StatusOK, gin.H{
		"status":  0,
		"message": "scan started",
		"data":    gin.H{"scan_id": scanID},
	})

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()

		ctx = plugin.WithProgress(ctx, func(current, total int, message string) {
			progress.update(current, total, message)
		})

		result, err := p.Scan(ctx, scanTarget)
		if err != nil {
			progress.mu.Lock()
			progress.Status = "failed"
			progress.Message = err.Error()
			progress.mu.Unlock()
			return
		}

		if api.storage != nil && result != nil {
			_ = api.storage.Save(result)
		}

		if req.AIAnalyze && api.aiManager != nil && result != nil {
			analysis, aerr := api.aiManager.Analyze([]*plugin.ScanResult{result})
			if aerr == nil && analysis != "" {
				result.RawOutput += "\n\n--- AI Analysis ---\n" + analysis
			}
		}

		progress.mu.Lock()
		progress.Status = "completed"
		progress.Result = result
		progress.Current = 100
		progress.Total = 100
		progress.Message = "Scan completed"
		progress.mu.Unlock()

		scanProgressStore.Store(scanID, progress)
	}()
}

func (api *PluginAPI) HandleScanProgress(c *gin.Context) {
	scanID := c.Param("id")
	val, ok := scanProgressStore.Load(scanID)
	if !ok {
		c.JSON(http.StatusOK, gin.H{
			"status":  1,
			"message": "scan not found",
			"data":    nil,
		})
		return
	}

	progress := val.(*scanProgress)
	snapshot := progress.getSnapshot()

	c.JSON(http.StatusOK, gin.H{
		"status":  0,
		"message": "ok",
		"data":    snapshot,
	})

	if snapshot.Status == "completed" || snapshot.Status == "failed" {
		scanProgressStore.Delete(scanID)
	}
}

func (api *PluginAPI) HandleFileUpload(c *gin.Context) {
	file, header, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status":  1,
			"message": "no file uploaded: " + err.Error(),
			"data":    nil,
		})
		return
	}
	defer file.Close()

	if header.Size > 10*1024*1024 {
		c.JSON(http.StatusOK, gin.H{
			"status":  1,
			"message": "file too large (max 10MB)",
			"data":    nil,
		})
		return
	}

	content, err := io.ReadAll(file)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status":  1,
			"message": "failed to read file: " + err.Error(),
			"data":    nil,
		})
		return
	}

	tmpDir := filepath.Join(os.TempDir(), "ai-sec-check-uploads")
	os.MkdirAll(tmpDir, 0o755)

	tmpFile := filepath.Join(tmpDir, fmt.Sprintf("%d_%s", time.Now().UnixNano(), header.Filename))
	if err := os.WriteFile(tmpFile, content, 0o644); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status":  1,
			"message": "failed to save file: " + err.Error(),
			"data":    nil,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  0,
		"message": "file uploaded",
		"data": gin.H{
			"file_path":    tmpFile,
			"file_name":    header.Filename,
			"file_size":    header.Size,
			"file_content": string(content),
		},
	})
}

type MultiScanRequest struct {
	Categories  []string               `json:"categories,omitempty"`
	PluginNames []string               `json:"plugin_names,omitempty"`
	TargetType  string                 `json:"target_type" binding:"required"`
	Target      string                 `json:"target" binding:"required"`
	Metadata    map[string]string      `json:"metadata,omitempty"`
	Params      map[string]interface{} `json:"params,omitempty"`
	AIAnalyze   bool                   `json:"ai_analyze,omitempty"`
}

func (api *PluginAPI) HandleMultiScan(c *gin.Context) {
	var req MultiScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status":  1,
			"message": "invalid parameters: " + err.Error(),
			"data":    nil,
		})
		return
	}

	scanTarget := plugin.ScanTarget{
		Type:     req.TargetType,
		Value:    req.Target,
		Metadata: req.Metadata,
	}

	cfg := plugin.PluginConfig{}
	if req.Params != nil {
		cfg = plugin.PluginConfig(req.Params)
	}

	orchestrator := plugin.NewOrchestrator(api.registry)

	var jobs []plugin.ScanJob
	if len(req.PluginNames) > 0 {
		for _, name := range req.PluginNames {
			jobs = append(jobs, plugin.ScanJob{
				PluginName: name,
				Target:     scanTarget,
				Config:     cfg,
			})
		}
	} else if len(req.Categories) > 0 {
		for _, cat := range req.Categories {
			plugins := api.registry.ListByCategory(cat)
			for _, p := range plugins {
				if p.IsAvailable() {
					jobs = append(jobs, plugin.ScanJob{
						PluginName: p.Name(),
						Target:     scanTarget,
						Config:     cfg,
					})
				}
			}
		}
	} else {
		plugins := api.registry.AvailablePlugins()
		for _, p := range plugins {
			jobs = append(jobs, plugin.ScanJob{
				PluginName: p.Name(),
				Target:     scanTarget,
				Config:     cfg,
			})
		}
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Minute)
	defer cancel()

	results := orchestrator.RunParallel(ctx, jobs)

	if api.storage != nil {
		for _, r := range results {
			if r.Result != nil && r.Error == nil {
				_ = api.storage.Save(r.Result)
			}
		}
	}

	response := gin.H{
		"status":  0,
		"message": "multi-scan completed",
		"data":    results,
	}

	if req.AIAnalyze && api.aiManager != nil {
		scanResults := make([]*plugin.ScanResult, 0)
		for _, r := range results {
			if r.Result != nil && r.Error == nil {
				scanResults = append(scanResults, r.Result)
			}
		}
		if len(scanResults) > 0 {
			analysis, err := api.aiManager.Analyze(scanResults)
			if err == nil && analysis != "" {
				response["ai_analysis"] = analysis
			}
		}
	}

	c.JSON(http.StatusOK, response)
}

func (api *PluginAPI) HandleGetScanResults(c *gin.Context) {
	category := c.Query("category")
	pluginName := c.Query("plugin_name")
	limit := 50

	results, err := api.storage.List(limit)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status":  1,
			"message": "failed to retrieve results: " + err.Error(),
			"data":    nil,
		})
		return
	}

	if category != "" {
		var filtered []*plugin.ScanResult
		for _, r := range results {
			if r.Category == category {
				filtered = append(filtered, r)
			}
		}
		results = filtered
	}
	if pluginName != "" {
		var filtered []*plugin.ScanResult
		for _, r := range results {
			if r.PluginName == pluginName {
				filtered = append(filtered, r)
			}
		}
		results = filtered
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  0,
		"message": "ok",
		"data":    results,
	})
}

func (api *PluginAPI) HandleGetScanResult(c *gin.Context) {
	id := c.Param("id")
	result, err := api.storage.Get(id)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status":  1,
			"message": "result not found",
			"data":    nil,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status":  0,
		"message": "ok",
		"data":    result,
	})
}

func (api *PluginAPI) HandleGetScanStats(c *gin.Context) {
	counts, err := api.storage.CountByCategory()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status":  1,
			"message": "failed to retrieve stats: " + err.Error(),
			"data":    nil,
		})
		return
	}
	total, _ := api.storage.Count()
	c.JSON(http.StatusOK, gin.H{
		"status":  0,
		"message": "ok",
		"data": gin.H{
			"total":       total,
			"by_category": counts,
		},
	})
}
