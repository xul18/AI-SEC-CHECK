package storage

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"ai-sec-check/internal/plugin"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type ScanResultRecord struct {
	ID          string         `gorm:"primaryKey;column:id" json:"id"`
	PluginName  string         `gorm:"column:plugin_name;index" json:"plugin_name"`
	Category    string         `gorm:"column:category;index" json:"category"`
	Target      string         `gorm:"column:target" json:"target"`
	Status      string         `gorm:"column:status" json:"status"`
	Findings    datatypes.JSON `gorm:"column:findings" json:"findings"`
	Summary     string         `gorm:"column:summary" json:"summary"`
	ScanTime    string         `gorm:"column:scan_time" json:"scan_time"`
	Duration    float64        `gorm:"column:duration" json:"duration"`
	RawOutput   string         `gorm:"column:raw_output;type:text" json:"raw_output,omitempty"`
	CreatedAt   int64          `gorm:"column:created_at;not null" json:"created_at"`
}

func (ScanResultRecord) TableName() string {
	return "scan_results"
}

type ScanResultStore struct {
	db *gorm.DB
}

func NewScanResultStore(db *gorm.DB) *ScanResultStore {
	return &ScanResultStore{db: db}
}

func (s *ScanResultStore) Init() error {
	return s.db.AutoMigrate(&ScanResultRecord{})
}

func (s *ScanResultStore) Save(result *plugin.ScanResult) error {
	findingsJSON, err := json.Marshal(result.Findings)
	if err != nil {
		return fmt.Errorf("failed to marshal findings: %w", err)
	}
	id := result.ID
	if id == "" {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return fmt.Errorf("failed to generate id: %w", err)
		}
		id = hex.EncodeToString(b)
	}
	record := &ScanResultRecord{
		ID:         id,
		PluginName: result.PluginName,
		Category:   result.Category,
		Target:     result.Target,
		Status:     result.Status,
		Findings:   findingsJSON,
		Summary:    result.Summary,
		ScanTime:   result.ScanTime,
		Duration:   result.Duration,
		RawOutput:  result.RawOutput,
		CreatedAt:  time.Now().UnixMilli(),
	}
	return s.db.Create(record).Error
}

func (s *ScanResultStore) Get(id string) (*plugin.ScanResult, error) {
	var record ScanResultRecord
	if err := s.db.First(&record, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return recordToResult(&record), nil
}

func (s *ScanResultStore) ListByCategory(category string, limit int) ([]*plugin.ScanResult, error) {
	var records []*ScanResultRecord
	query := s.db.Where("category = ?", category).Order("created_at DESC")
	if limit > 0 {
		query = query.Limit(limit)
	}
	if err := query.Find(&records).Error; err != nil {
		return nil, err
	}
	return recordsToResults(records), nil
}

func (s *ScanResultStore) ListByPlugin(pluginName string, limit int) ([]*plugin.ScanResult, error) {
	var records []*ScanResultRecord
	query := s.db.Where("plugin_name = ?", pluginName).Order("created_at DESC")
	if limit > 0 {
		query = query.Limit(limit)
	}
	if err := query.Find(&records).Error; err != nil {
		return nil, err
	}
	return recordsToResults(records), nil
}

func (s *ScanResultStore) List(limit int) ([]*plugin.ScanResult, error) {
	var records []*ScanResultRecord
	query := s.db.Order("created_at DESC")
	if limit > 0 {
		query = query.Limit(limit)
	}
	if err := query.Find(&records).Error; err != nil {
		return nil, err
	}
	return recordsToResults(records), nil
}

func (s *ScanResultStore) Delete(id string) error {
	return s.db.Delete(&ScanResultRecord{}, "id = ?", id).Error
}

func (s *ScanResultStore) Count() (int64, error) {
	var count int64
	err := s.db.Model(&ScanResultRecord{}).Count(&count).Error
	return count, err
}

func (s *ScanResultStore) CountByCategory() (map[string]int64, error) {
	type categoryCount struct {
		Category string
		Count    int64
	}
	var results []categoryCount
	err := s.db.Model(&ScanResultRecord{}).Select("category, count(*) as count").Group("category").Find(&results).Error
	if err != nil {
		return nil, err
	}
	counts := make(map[string]int64)
	for _, r := range results {
		counts[r.Category] = r.Count
	}
	return counts, nil
}

func recordToResult(record *ScanResultRecord) *plugin.ScanResult {
	var findings []plugin.Finding
	if record.Findings != nil {
		json.Unmarshal(record.Findings, &findings)
	}
	return &plugin.ScanResult{
		ID:         record.ID,
		PluginName: record.PluginName,
		Category:   record.Category,
		Target:     record.Target,
		Status:     record.Status,
		Findings:   findings,
		Summary:    record.Summary,
		ScanTime:   record.ScanTime,
		Duration:   record.Duration,
		RawOutput:  record.RawOutput,
	}
}

func recordsToResults(records []*ScanResultRecord) []*plugin.ScanResult {
	results := make([]*plugin.ScanResult, 0, len(records))
	for _, r := range records {
		results = append(results, recordToResult(r))
	}
	return results
}

func ExportToJSON(result *plugin.ScanResult, outputDir string) (string, error) {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", err
	}
	filename := fmt.Sprintf("%s_%s_%d.json", result.PluginName, result.Category, time.Now().Unix())
	path := filepath.Join(outputDir, filename)
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", err
	}
	return path, os.WriteFile(path, data, 0644)
}
