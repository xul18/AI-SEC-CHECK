package plugin

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	sensitive "github.com/LuYongwang/go-sensitive-word"
)

type SensitiveWordPlugin struct {
	config  PluginConfig
	manager *sensitive.Manager
}

func NewSensitiveWordPlugin() *SensitiveWordPlugin {
	return &SensitiveWordPlugin{}
}

func (p *SensitiveWordPlugin) Name() string {
	return "sensitive_word"
}

func (p *SensitiveWordPlugin) Category() string {
	return CategoryContentSafety
}

func (p *SensitiveWordPlugin) Description() string {
	return "Content safety / sensitive word detection (based on go-sensitive-word)"
}

func (p *SensitiveWordPlugin) Init(config PluginConfig) error {
	p.config = config

	filterType := uint32(sensitive.FilterDfa)
	algorithm := config.GetString("algorithm")
	if algorithm == "ac" {
		filterType = uint32(sensitive.FilterAC)
	}

	manager, err := sensitive.NewFilter(
		sensitive.StoreOption{Type: sensitive.StoreMemory},
		sensitive.FilterOption{Type: filterType},
	)
	if err != nil {
		return fmt.Errorf("failed to create sensitive word filter: %w", err)
	}

	dicts := config.GetStringSlice("dicts")
	if len(dicts) == 0 {
		dicts = []string{"political", "violence", "pornography", "reactionary",
			"advertisement", "corruption", "gun_explosion", "people_life"}
	}

	dictMap := map[string]struct {
		content string
		name    string
	}{
		"political":     {sensitive.DictPolitical, "political"},
		"violence":      {sensitive.DictViolence, "violence"},
		"pornography":   {sensitive.DictPornography, "pornography"},
		"reactionary":   {sensitive.DictReactionary, "reactionary"},
		"advertisement": {sensitive.DictAdvertisement, "advertisement"},
		"corruption":    {sensitive.DictCorruption, "corruption"},
		"gun_explosion": {sensitive.DictGunExplosion, "gun_explosion"},
		"people_life":   {sensitive.DictPeopleLife, "people_life"},
	}

	for _, dictName := range dicts {
		if d, ok := dictMap[dictName]; ok {
			if err := manager.LoadDictEmbedWithSource(d.content, d.name); err != nil {
				return fmt.Errorf("failed to load dict %s: %w", dictName, err)
			}
		}
	}

	customDictPath := config.GetString("custom_dict_path")
	if customDictPath != "" {
		if _, err := os.Stat(customDictPath); err == nil {
			if err := manager.RefreshFromPath(customDictPath, false); err != nil {
				return fmt.Errorf("failed to load custom dict from %s: %w", customDictPath, err)
			}
		}
	}

	p.manager = manager
	return nil
}

func (p *SensitiveWordPlugin) Scan(ctx context.Context, target ScanTarget) (*ScanResult, error) {
	result := &ScanResult{
		PluginName: p.Name(),
		Category:   p.Category(),
		Target:     target.Value,
		Status:     StatusCompleted,
		Findings:   []Finding{},
	}

	if p.manager == nil {
		result.Status = StatusFailed
		result.Summary = "sensitive word manager not initialized"
		return result, nil
	}

	var text string

	switch target.Type {
	case TargetTypeText:
		text = target.Value
	case TargetTypeFile:
		data, readErr := os.ReadFile(target.Value)
		if readErr != nil {
			result.Status = StatusFailed
			result.Summary = fmt.Sprintf("failed to read file: %s", readErr.Error())
			return result, nil
		}
		
		fileName := target.Value
		if strings.HasSuffix(strings.ToLower(fileName), ".docx") {
			docxText, docxErr := ExtractTextFromDocx(data)
			if docxErr != nil {
				result.Status = StatusFailed
				result.Summary = fmt.Sprintf("failed to parse docx file: %s", docxErr.Error())
				return result, nil
			}
			text = docxText
		} else {
			text = string(data)
		}
	default:
		result.Status = StatusFailed
		result.Summary = fmt.Sprintf("unsupported target type: %s", target.Type)
		return result, nil
	}

	findings := p.scanText(text)
	result.Findings = findings

	if len(findings) > 0 {
		result.Summary = fmt.Sprintf("Found %d sensitive word(s) in %s", len(findings), target.Type)
	} else {
		result.Summary = fmt.Sprintf("No sensitive words found in %s", target.Type)
	}

	return result, nil
}

func (p *SensitiveWordPlugin) scanText(text string) []Finding {
	if len(text) == 0 {
		return []Finding{}
	}

	matchResults := p.manager.FindAllWithSource(text)
	findings := make([]Finding, 0, len(matchResults))

	seen := make(map[string]bool)
	for _, mr := range matchResults {
		key := mr.Word
		if seen[key] {
			continue
		}
		seen[key] = true

		sources := strings.Join(mr.Source, ", ")
		findings = append(findings, Finding{
			Severity:    SeverityHigh,
			Title:       fmt.Sprintf("Sensitive word detected: %s", mr.Word),
			Description: fmt.Sprintf("Sensitive word found from dict: %s", sources),
			RuleID:      fmt.Sprintf("SW-%s", strings.ToUpper(sources)),
			Evidence:    mr.Word,
			Remediation: "Review and remove or replace the sensitive content",
			Source:      sources,
		})
	}

	return findings
}

func (p *SensitiveWordPlugin) ScanStream(ctx context.Context, textCh <-chan string) ([]Finding, error) {
	allFindings := make([]Finding, 0)
	for {
		select {
		case <-ctx.Done():
			return allFindings, ctx.Err()
		case text, ok := <-textCh:
			if !ok {
				return allFindings, nil
			}
			findings := p.scanText(text)
			allFindings = append(allFindings, findings...)
		}
	}
}

func (p *SensitiveWordPlugin) IsSensitive(text string) bool {
	if p.manager == nil {
		return false
	}
	return p.manager.IsSensitive(text)
}

func (p *SensitiveWordPlugin) Replace(text string, repl rune) string {
	if p.manager == nil {
		return text
	}
	return p.manager.Replace(text, repl)
}

func (p *SensitiveWordPlugin) GetStats() (totalWords int, sources []string) {
	if p.manager == nil {
		return 0, nil
	}
	stats := p.manager.GetStats()
	return stats.TotalWords, stats.Source
}

func (p *SensitiveWordPlugin) IsAvailable() bool {
	return p.manager != nil
}

func (p *SensitiveWordPlugin) ValidateTarget(target ScanTarget) error {
	switch target.Type {
	case TargetTypeText:
		if strings.TrimSpace(target.Value) == "" {
			return fmt.Errorf("text content cannot be empty")
		}
		return nil
	case TargetTypeFile:
		if _, err := os.Stat(target.Value); os.IsNotExist(err) {
			return fmt.Errorf("file not found: %s", target.Value)
		}
		return nil
	default:
		return fmt.Errorf("unsupported target type: %s, expected text/file", target.Type)
	}
}

func maskWord(word string) string {
	runes := []rune(word)
	length := len(runes)
	if length <= 1 {
		return "*"
	}
	if length <= 3 {
		return string(runes[0]) + strings.Repeat("*", length-1)
	}
	return string(runes[0]) + strings.Repeat("*", length-2) + string(runes[length-1])
}

func LoadWordsFromFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var words []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			words = append(words, line)
		}
	}
	return words, scanner.Err()
}

var xmlTagRe = regexp.MustCompile(`<[^>]+>`)

func ExtractTextFromDocx(data []byte) (string, error) {
	reader := bytes.NewReader(data)
	zr, err := zip.NewReader(reader, int64(len(data)))
	if err != nil {
		return "", fmt.Errorf("invalid docx file: %w", err)
	}

	var documentXML string
	for _, f := range zr.File {
		if f.Name == "word/document.xml" {
			fh, err := f.Open()
			if err != nil {
				return "", fmt.Errorf("failed to open document.xml: %w", err)
			}
			content, err := io.ReadAll(fh)
			fh.Close()
			if err != nil {
				return "", fmt.Errorf("failed to read document.xml: %w", err)
			}
			documentXML = string(content)
			break
		}
	}

	if documentXML == "" {
		return "", fmt.Errorf("document.xml not found in docx file")
	}

	text := xmlTagRe.ReplaceAllString(documentXML, "")
	text = strings.ReplaceAll(text, "&#160;", " ")
	text = strings.ReplaceAll(text, "&nbsp;", " ")
	
	var result strings.Builder
	lines := strings.Split(text, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			if result.Len() > 0 {
				result.WriteString("\n")
			}
			result.WriteString(line)
		}
	}

	return result.String(), nil
}
