package plugin

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"

	sensitive "github.com/LuYongwang/go-sensitive-word"
	"github.com/PuerkitoBio/goquery"
	"github.com/comend/goxls/pkg/ole2"
	"github.com/ledongthuc/pdf"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
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
		var data []byte
		var fileName string

		if strings.HasPrefix(target.Value, "data:") {
			var fileData []byte
			var contentType string
			fileData, contentType, fileName = parseDataURL(target.Value)
			data = fileData

			if fileName == "" {
				if name, ok := target.Metadata["file_name"]; ok && name != "" {
					fileName = name
				} else if strings.Contains(contentType, "pdf") {
					fileName = "temp.pdf"
				} else if strings.Contains(contentType, "docx") {
					fileName = "temp.docx"
				} else if strings.Contains(contentType, "word") {
					fileName = "temp.docx"
				} else {
					fileName = "temp.txt"
				}
			}
		} else {
			var readErr error
			data, readErr = os.ReadFile(target.Value)
			if readErr != nil {
				result.Status = StatusFailed
				result.Summary = fmt.Sprintf("failed to read file: %s", readErr.Error())
				return result, nil
			}
			fileName = target.Value
		}

		ext := strings.ToLower(fileName[strings.LastIndex(fileName, "."):])

		switch ext {
		case ".docx", ".docm", ".dotx", ".dotm":
			docxText, docxErr := ExtractTextFromDocx(data)
			if docxErr != nil {
				result.Status = StatusFailed
				result.Summary = fmt.Sprintf("failed to parse document file: %s", docxErr.Error())
				return result, nil
			}
			text = docxText
		case ".pdf":
			pdfText, pdfErr := ExtractTextFromPDF(data)
			if pdfErr != nil {
				result.Status = StatusFailed
				result.Summary = fmt.Sprintf("failed to parse pdf file: %s", pdfErr.Error())
				return result, nil
			}
			text = pdfText
		case ".xlsx", ".xlsb", ".xlsm", ".et", ".ett":
			xlsxText, xlsxErr := ExtractTextFromXlsx(data)
			if xlsxErr != nil {
				result.Status = StatusFailed
				result.Summary = fmt.Sprintf("failed to parse excel file: %s", xlsxErr.Error())
				return result, nil
			}
			text = xlsxText
		case ".doc", ".xls", ".wps":
			if ext == ".doc" {
				text = p.scanDocFile(data)
			} else {
				legacyText, legacyErr := ExtractTextFromLegacyOffice(data, ext)
				if legacyErr != nil {
					result.Status = StatusFailed
					result.Summary = fmt.Sprintf("failed to parse legacy office file: %s", legacyErr.Error())
					return result, nil
				}
				text = legacyText
			}
		default:
			text = decodeTextContent(data)
		}
	default:
		result.Status = StatusFailed
		result.Summary = fmt.Sprintf("unsupported target type: %s", target.Type)
		return result, nil
	}

	text = p.extractAnswerText(text)

	findings := p.scanText(text)
	result.Findings = findings

	if len(findings) > 0 {
		result.Summary = fmt.Sprintf("Found %d sensitive word(s) in %s", len(findings), target.Type)
	} else {
		result.Summary = fmt.Sprintf("No sensitive words found in %s", target.Type)
	}

	return result, nil
}

func (p *SensitiveWordPlugin) detectSensitiveInBinary(data []byte) string {
	if p.manager == nil {
		return ""
	}

	allTexts := []string{
		extractAllTextFromBinary(data),
		extractTextFromDocSimple(data),
		decodeUTF16LE(data),
	}

	gbkText, err := decodeGBK(data)
	if err == nil {
		allTexts = append(allTexts, gbkText)
	}

	utf16beText := decodeUTF16BE(data)
	allTexts = append(allTexts, utf16beText)

	for _, text := range allTexts {
		if p.manager.IsSensitive(text) {
			return text
		}
	}

	wordData := extractWordsFromBinary(data)
	if p.manager.IsSensitive(wordData) {
		return wordData
	}

	foundWords := p.searchSensitiveWordsInBinary(data)
	if len(foundWords) > 0 {
		return strings.Join(foundWords, " ")
	}

	return ""
}

func (p *SensitiveWordPlugin) scanDocFile(data []byte) string {
	if p.manager == nil {
		return ""
	}

	extractors := []func([]byte) string{
		extractTextFromDocWithOLE2,
		extractTextFromWordOLE2,
		extractAllTextFromBinary,
		extractTextFromDocSimple,
		decodeUTF16LE,
		decodeUTF16BE,
		extractWordsFromBinary,
		extractTextFromRTF,
	}

	for _, extractor := range extractors {
		text := extractor(data)
		if text != "" && p.manager.IsSensitive(text) {
			return text
		}
	}

	gbkText, err := decodeGBK(data)
	if err == nil && gbkText != "" && p.manager.IsSensitive(gbkText) {
		return gbkText
	}

	foundWords := p.searchSensitiveWordsInBinary(data)
	if len(foundWords) > 0 {
		return strings.Join(foundWords, " ")
	}

	allText := extractAllTextFromBinary(data)
	if allText == "" {
		allText = decodeUTF16LE(data)
	}
	if allText == "" {
		allText = extractTextFromDocSimple(data)
	}

	return allText
}

func extractTextFromDocWithOLE2(data []byte) string {
	reader := bytes.NewReader(data)

	ole, err := ole2.Open(reader, "GBK")
	if err != nil {
		return ""
	}

	files, err := ole.ListDir()
	if err != nil {
		return ""
	}

	var wordDoc *ole2.File
	for _, f := range files {
		if strings.EqualFold(strings.TrimSpace(f.Name()), "WordDocument") {
			wordDoc = f
			break
		}
	}

	if wordDoc == nil {
		return ""
	}

	root, err := ole.ListDir()
	if err != nil {
		return ""
	}

	var rootFile *ole2.File
	for _, f := range root {
		if f.Type == ole2.ROOT {
			rootFile = f
			break
		}
	}

	if rootFile == nil && len(root) > 0 {
		rootFile = root[0]
	}

	if rootFile == nil {
		return ""
	}

	stream := ole.OpenFile(wordDoc, rootFile)
	if stream == nil {
		return ""
	}

	streamData, err := io.ReadAll(stream)
	if err != nil {
		return ""
	}

	return extractTextFromWordBinaryStream(streamData)
}

func extractTextFromWordBinaryStream(data []byte) string {
	var result strings.Builder

	if len(data) < 512 {
		return ""
	}

	textOffset := binary.LittleEndian.Uint32(data[44:48])
	textLength := binary.LittleEndian.Uint32(data[48:52])

	if textOffset == 0 || textLength == 0 {
		textOffset = 0
		textLength = uint32(len(data))
	}

	if textOffset+textLength > uint32(len(data)) {
		textLength = uint32(len(data)) - textOffset
	}

	textData := data[textOffset : textOffset+textLength]

	for i := 0; i < len(textData); {
		if i+1 < len(textData) {
			if textData[i] != 0x00 && textData[i+1] != 0x00 {
				high := textData[i]
				low := textData[i+1]

				if high >= 0x4E && high <= 0x9F {
					code := uint16(low) | (uint16(high) << 8)
					char := rune(code)
					if char >= 0x4E00 && char <= 0x9FFF {
						result.WriteRune(char)
						i += 2
						continue
					}
				}

				if high >= 0x81 && high <= 0xFE && low >= 0x40 && low <= 0xFE && low != 0x7F {
					utf8Text, err := gbkToUTF8([]byte{high, low})
					if err == nil {
						result.WriteString(utf8Text)
					}
					i += 2
					continue
				}
			} else if textData[i] == 0x00 && textData[i+1] != 0x00 {
				code := uint16(textData[i+1]) | (uint16(textData[i]) << 8)
				if code >= 0x4E00 && code <= 0x9FFF {
					result.WriteRune(rune(code))
					i += 2
					continue
				}
				if textData[i+1] >= 0x20 && textData[i+1] <= 0x7E {
					result.WriteByte(textData[i+1])
					i += 2
					continue
				}
			}
		}

		if textData[i] >= 0x20 && textData[i] <= 0x7E {
			result.WriteByte(textData[i])
		} else if textData[i] == 0x0D || textData[i] == 0x0A {
			if result.Len() > 0 && result.String()[result.Len()-1] != '\n' {
				result.WriteString("\n")
			}
		}
		i++
	}

	return cleanExtractedText(result.String())
}

func extractTextFromRTF(data []byte) string {
	rtfStart := bytes.Index(data, []byte("{\\rtf"))
	if rtfStart == -1 {
		rtfStart = bytes.Index(data, []byte("\\rtf"))
	}

	if rtfStart == -1 {
		return ""
	}

	rtfEnd := bytes.LastIndex(data, []byte("}"))
	if rtfEnd == -1 || rtfEnd <= rtfStart {
		return ""
	}

	rtfData := string(data[rtfStart : rtfEnd+1])

	rtfData = regexp.MustCompile(`\\[a-zA-Z]+\s*\d*`).ReplaceAllString(rtfData, " ")
	rtfData = regexp.MustCompile(`\{\s*[a-zA-Z]+\s*\}`).ReplaceAllString(rtfData, " ")
	rtfData = regexp.MustCompile(`\{|\}`).ReplaceAllString(rtfData, " ")
	rtfData = regexp.MustCompile(`\s+`).ReplaceAllString(rtfData, " ")

	return strings.TrimSpace(rtfData)
}

func (p *SensitiveWordPlugin) searchSensitiveWordsInBinary(data []byte) []string {
	var foundWords []string

	dicts := []string{
		sensitive.DictPolitical,
		sensitive.DictViolence,
		sensitive.DictPornography,
		sensitive.DictReactionary,
		sensitive.DictAdvertisement,
		sensitive.DictCorruption,
		sensitive.DictGunExplosion,
		sensitive.DictPeopleLife,
	}

	for _, dictContent := range dicts {
		scanner := bufio.NewScanner(strings.NewReader(dictContent))
		for scanner.Scan() {
			word := strings.TrimSpace(scanner.Text())
			if word == "" {
				continue
			}

			if p.manager.IsSensitive(word) {
				gbkWord, err := utf8ToGBK(word)
				if err == nil && bytes.Contains(data, gbkWord) {
					foundWords = append(foundWords, word)
					continue
				}

				utf16leWord := utf8ToUTF16LE(word)
				if bytes.Contains(data, utf16leWord) {
					foundWords = append(foundWords, word)
					continue
				}

				utf16beWord := utf8ToUTF16BE(word)
				if bytes.Contains(data, utf16beWord) {
					foundWords = append(foundWords, word)
					continue
				}

				if bytes.Contains(data, []byte(word)) {
					foundWords = append(foundWords, word)
					continue
				}
			}
		}
	}

	seen := make(map[string]bool)
	result := make([]string, 0)
	for _, w := range foundWords {
		if !seen[w] {
			seen[w] = true
			result = append(result, w)
		}
	}

	return result
}

func utf8ToGBK(s string) ([]byte, error) {
	encoder := simplifiedchinese.GBK.NewEncoder()
	result, _, err := transform.Bytes(encoder, []byte(s))
	if err != nil {
		return nil, err
	}
	return result, nil
}

func utf8ToUTF16LE(s string) []byte {
	runes := []rune(s)
	result := make([]byte, 0, len(runes)*2)
	for _, r := range runes {
		result = append(result, byte(r), byte(r>>8))
	}
	return result
}

func utf8ToUTF16BE(s string) []byte {
	runes := []rune(s)
	result := make([]byte, 0, len(runes)*2)
	for _, r := range runes {
		result = append(result, byte(r>>8), byte(r))
	}
	return result
}

func decodeUTF16BE(data []byte) string {
	var result strings.Builder
	for i := 0; i+1 < len(data); i += 2 {
		if data[i] != 0x00 || data[i+1] != 0x00 {
			code := uint16(data[i+1]) | (uint16(data[i]) << 8)
			if code >= 0x20 && code <= 0x7E {
				result.WriteByte(data[i+1])
			} else if code >= 0x4E00 && code <= 0x9FFF {
				result.WriteRune(rune(code))
			}
		}
	}
	return result.String()
}

func extractWordsFromBinary(data []byte) string {
	var result strings.Builder

	for i := 0; i < len(data); i++ {
		if data[i] >= 0x20 && data[i] <= 0x7E {
			start := i
			for i < len(data) && (data[i] >= 0x20 && data[i] <= 0x7E ||
				data[i] == 0x0A || data[i] == 0x0D || data[i] == 0x09) {
				i++
			}
			if i-start >= 2 {
				if result.Len() > 0 {
					result.WriteString(" ")
				}
				result.WriteString(string(data[start:i]))
			}
		}
	}

	for i := 0; i < len(data)-1; i++ {
		if data[i] >= 0x81 && data[i] <= 0xFE && data[i+1] >= 0x40 && data[i+1] <= 0xFE && data[i+1] != 0x7F {
			utf8Text, err := gbkToUTF8([]byte{data[i], data[i+1]})
			if err == nil {
				result.WriteString(utf8Text)
			}
			i++
		}
	}

	return result.String()
}

func decodeUTF16LE(data []byte) string {
	var result strings.Builder
	for i := 0; i+1 < len(data); i += 2 {
		if data[i] != 0x00 || data[i+1] != 0x00 {
			code := uint16(data[i]) | (uint16(data[i+1]) << 8)
			if code >= 0x20 && code <= 0x7E {
				result.WriteByte(data[i])
			} else if code >= 0x4E00 && code <= 0x9FFF {
				result.WriteRune(rune(code))
			}
		}
	}
	return result.String()
}

func decodeGBK(data []byte) (string, error) {
	decoder := simplifiedchinese.GBK.NewDecoder()
	result, _, err := transform.Bytes(decoder, data)
	if err != nil {
		return "", err
	}
	return string(result), nil
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

func ExtractTextFromPDF(data []byte) (string, error) {
	tmpFile, err := os.CreateTemp("", "scan_*.pdf")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		return "", fmt.Errorf("failed to write temp file: %w", err)
	}
	tmpFile.Close()

	f, r, err := pdf.Open(tmpPath)
	if err != nil {
		return "", fmt.Errorf("failed to open pdf file: %w", err)
	}
	defer f.Close()

	var result strings.Builder
	for pageIndex := 1; pageIndex <= r.NumPage(); pageIndex++ {
		p := r.Page(pageIndex)
		if p.V.IsNull() {
			continue
		}

		text, err := p.GetPlainText(nil)
		if err != nil {
			return "", fmt.Errorf("failed to extract text from page %d: %w", pageIndex, err)
		}

		if result.Len() > 0 {
			result.WriteString("\n")
		}
		result.WriteString(text)
	}

	return cleanExtractedText(result.String()), nil
}

func ExtractTextFromXlsx(data []byte) (string, error) {
	reader := bytes.NewReader(data)
	zr, err := zip.NewReader(reader, int64(len(data)))
	if err != nil {
		return "", fmt.Errorf("invalid xlsx file: %w", err)
	}

	var sharedStrings []string
	for _, f := range zr.File {
		if f.Name == "xl/sharedStrings.xml" {
			fh, err := f.Open()
			if err != nil {
				return "", fmt.Errorf("failed to open sharedStrings.xml: %w", err)
			}
			content, err := io.ReadAll(fh)
			fh.Close()
			if err != nil {
				return "", fmt.Errorf("failed to read sharedStrings.xml: %w", err)
			}
			sharedStrings = parseSharedStrings(string(content))
			break
		}
	}

	var result strings.Builder
	for _, f := range zr.File {
		if strings.HasPrefix(f.Name, "xl/worksheets/sheet") && strings.HasSuffix(f.Name, ".xml") {
			fh, err := f.Open()
			if err != nil {
				continue
			}
			content, err := io.ReadAll(fh)
			fh.Close()
			if err != nil {
				continue
			}
			sheetText := parseXlsxSheet(string(content), sharedStrings)
			if result.Len() > 0 {
				result.WriteString("\n")
			}
			result.WriteString(sheetText)
		}
	}

	return result.String(), nil
}

func parseSharedStrings(xmlContent string) []string {
	var result []string
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(xmlContent))
	if err != nil {
		return result
	}
	doc.Find("t").Each(func(i int, s *goquery.Selection) {
		result = append(result, s.Text())
	})
	return result
}

func parseXlsxSheet(xmlContent string, sharedStrings []string) string {
	var result strings.Builder
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(xmlContent))
	if err != nil {
		return ""
	}

	doc.Find("row").Each(func(rowIdx int, row *goquery.Selection) {
		row.Find("c").Each(func(colIdx int, cell *goquery.Selection) {
			cellType, _ := cell.Attr("t")
			if cellType == "s" {
				vText := cell.Find("v").Text()
				var idx int
				fmt.Sscanf(vText, "%d", &idx)
				if idx >= 0 && idx < len(sharedStrings) {
					result.WriteString(sharedStrings[idx])
				}
			} else {
				vText := cell.Find("v").Text()
				result.WriteString(vText)
			}
			result.WriteString("\t")
		})
		result.WriteString("\n")
	})

	return result.String()
}

func ExtractTextFromLegacyOffice(data []byte, ext string) (string, error) {
	if ext == ".doc" {
		return extractTextFromDoc(data)
	}
	return extractTextFromXls(data)
}

func extractTextFromDoc(data []byte) (string, error) {
	extractors := []func([]byte) string{
		decodeUTF16LE,
		decodeUTF16BE,
		extractTextFromDocWithOLE2,
		extractTextFromWordOLE2,
		extractAllTextFromBinary,
		extractTextFromDocSimple,
		extractWordsFromBinary,
		extractTextFromRTF,
	}

	for _, extractor := range extractors {
		text := extractor(data)
		if text != "" {
			hasChinese := false
			for _, r := range text {
				if r >= 0x4E00 && r <= 0x9FFF {
					hasChinese = true
					break
				}
			}
			if hasChinese {
				return text, nil
			}
		}
	}

	gbkText, err := decodeGBK(data)
	if err == nil && gbkText != "" {
		hasChinese := false
		for _, r := range gbkText {
			if r >= 0x4E00 && r <= 0x9FFF {
				hasChinese = true
				break
			}
		}
		if hasChinese {
			return gbkText, nil
		}
	}

	for _, extractor := range extractors {
		text := extractor(data)
		if text != "" {
			return text, nil
		}
	}

	return "", nil
}

func extractTextFromDocSimple(data []byte) string {
	var result strings.Builder

	for i := 0; i < len(data)-1; i++ {
		if data[i] == 0x00 && data[i+1] != 0x00 {
			if data[i+1] >= 0x20 && data[i+1] <= 0x7E {
				start := i
				for i+1 < len(data) && data[i] == 0x00 && data[i+1] != 0x00 && data[i+1] >= 0x20 && data[i+1] <= 0x7E {
					result.WriteByte(data[i+1])
					i += 2
				}
				if i-start >= 4 {
					if result.Len() > 0 && result.String()[result.Len()-1] != '\n' {
						result.WriteString("\n")
					}
				}
			} else if data[i+1] >= 0x4E && data[i+1] <= 0x9F {
				if i+3 < len(data) && data[i+2] == 0x00 {
					code := uint16(data[i+1]) | (uint16(data[i+3]) << 8)
					if code >= 0x4E00 && code <= 0x9FFF {
						result.WriteRune(rune(code))
						i += 4
					} else {
						i++
					}
				} else {
					i++
				}
			} else {
				i++
			}
		} else if data[i] != 0x00 && data[i+1] != 0x00 {
			if data[i] >= 0x81 && data[i] <= 0xFE && data[i+1] >= 0x40 && data[i+1] <= 0xFE && data[i+1] != 0x7F {
				utf8Text, err := gbkToUTF8([]byte{data[i], data[i+1]})
				if err == nil {
					result.WriteString(utf8Text)
				}
				i += 2
				continue
			}
			i++
		} else {
			i++
		}
	}

	return cleanExtractedText(result.String())
}

func extractTextFromWordOLE2(data []byte) string {
	if len(data) < 512 {
		return ""
	}

	header := data[0:512]
	if string(header[0:8]) != "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" {
		return ""
	}

	byteOrder := binary.LittleEndian.Uint16(header[28:30])
	if byteOrder != 0xFFFE {
		return ""
	}

	sectorSize := int(binary.LittleEndian.Uint16(header[30:32]))
	if sectorSize == 0 {
		sectorSize = 512
	} else {
		sectorSize = 1 << sectorSize
	}

	miniSectorSize := int(binary.LittleEndian.Uint16(header[32:34]))
	if miniSectorSize == 0 {
		miniSectorSize = 64
	} else {
		miniSectorSize = 1 << miniSectorSize
	}

	numDirSectors := binary.LittleEndian.Uint32(header[44:48])
	firstDirSector := binary.LittleEndian.Uint32(header[48:52])

	fatStart := binary.LittleEndian.Uint32(header[36:40])
	numFatSectors := binary.LittleEndian.Uint32(header[40:44])

	fat := make([]uint32, 0, int(numFatSectors)*sectorSize/4)
	sectorIdx := fatStart
	for i := uint32(0); i < numFatSectors && sectorIdx != 0xFFFFFFFE && sectorIdx != 0xFFFFFFF; i++ {
		if int(sectorIdx)*sectorSize+sectorSize > len(data) {
			break
		}
		sector := data[sectorIdx*uint32(sectorSize) : sectorIdx*uint32(sectorSize)+uint32(sectorSize)]
		for j := 0; j < sectorSize; j += 4 {
			fat = append(fat, binary.LittleEndian.Uint32(sector[j:j+4]))
		}
		sectorIdx = fat[sectorIdx]
	}

	miniFatStart := binary.LittleEndian.Uint32(header[60:64])
	numMiniFatSectors := binary.LittleEndian.Uint32(header[64:68])
	miniFat := make([]uint32, 0, int(numMiniFatSectors)*sectorSize/4)
	sectorIdx = miniFatStart
	for i := uint32(0); i < numMiniFatSectors && sectorIdx != 0xFFFFFFFE && sectorIdx != 0xFFFFFFF; i++ {
		if int(sectorIdx)*sectorSize+sectorSize > len(data) {
			break
		}
		sector := data[sectorIdx*uint32(sectorSize) : sectorIdx*uint32(sectorSize)+uint32(sectorSize)]
		for j := 0; j < sectorSize; j += 4 {
			miniFat = append(miniFat, binary.LittleEndian.Uint32(sector[j:j+4]))
		}
		if int(sectorIdx) < len(fat) {
			sectorIdx = fat[sectorIdx]
		} else {
			break
		}
	}

	dirData := make([]byte, 0, int(numDirSectors)*sectorSize)
	sectorIdx = firstDirSector
	for i := uint32(0); i < numDirSectors && sectorIdx != 0xFFFFFFFE && sectorIdx != 0xFFFFFFF; i++ {
		if int(sectorIdx)*sectorSize+sectorSize > len(data) {
			break
		}
		dirData = append(dirData, data[sectorIdx*uint32(sectorSize):sectorIdx*uint32(sectorSize)+uint32(sectorSize)]...)
		if int(sectorIdx) < len(fat) {
			sectorIdx = fat[sectorIdx]
		} else {
			break
		}
	}

	var wordDocumentStream []byte
	for i := 0; i < len(dirData); i += 128 {
		if i+128 > len(dirData) {
			break
		}
		nameLen := int(dirData[i+64])
		if nameLen > 64 {
			continue
		}
		name := string(dirData[i : i+nameLen/2])
		name = strings.TrimSuffix(name, "\x00")

		if strings.EqualFold(name, "WordDocument") {
			streamType := dirData[i+116]
			if streamType != 2 {
				continue
			}

			size := binary.LittleEndian.Uint64(dirData[i+116+8 : i+116+16])
			firstSector := binary.LittleEndian.Uint32(dirData[i+116+16 : i+116+20])

			wordDocumentStream = make([]byte, 0, size)
			if size < uint64(4096) {
				sectorIdx = firstSector
				for sectorIdx != 0xFFFFFFFE && sectorIdx != 0xFFFFFFF {
					if int(sectorIdx)*miniSectorSize+miniSectorSize > len(data) {
						break
					}
					wordDocumentStream = append(wordDocumentStream, data[sectorIdx*uint32(miniSectorSize):sectorIdx*uint32(miniSectorSize)+uint32(miniSectorSize)]...)
					if int(sectorIdx) < len(miniFat) {
						sectorIdx = miniFat[sectorIdx]
					} else {
						break
					}
				}
			} else {
				sectorIdx = firstSector
				for sectorIdx != 0xFFFFFFFE && sectorIdx != 0xFFFFFFF {
					if int(sectorIdx)*sectorSize+sectorSize > len(data) {
						break
					}
					wordDocumentStream = append(wordDocumentStream, data[sectorIdx*uint32(sectorSize):sectorIdx*uint32(sectorSize)+uint32(sectorSize)]...)
					if int(sectorIdx) < len(fat) {
						sectorIdx = fat[sectorIdx]
					} else {
						break
					}
				}
			}
			break
		}
	}

	if len(wordDocumentStream) == 0 {
		return ""
	}

	return extractTextFromWordStream(wordDocumentStream)
}

func extractTextFromWordStream(data []byte) string {
	var result strings.Builder

	if len(data) > 512 {
		textOffset := binary.LittleEndian.Uint32(data[44:48])
		textLength := binary.LittleEndian.Uint32(data[48:52])

		if textOffset > 0 && textOffset+textLength < uint32(len(data)) {
			textData := data[textOffset : textOffset+textLength]

			for i := 0; i < len(textData); {
				if i+1 < len(textData) && textData[i] != 0x00 && textData[i+1] != 0x00 {
					high := textData[i]
					low := textData[i+1]

					if high >= 0x4E && high <= 0x9F {
						code := uint16(low) | (uint16(high) << 8)
						char := rune(code)
						if char >= 0x4E00 && char <= 0x9FFF {
							result.WriteRune(char)
							i += 2
							continue
						}
					}

					if high >= 0x81 && high <= 0xFE && low >= 0x40 && low <= 0xFE && low != 0x7F {
						utf8Text, err := gbkToUTF8([]byte{high, low})
						if err == nil {
							result.WriteString(utf8Text)
						}
						i += 2
						continue
					}
				}

				if textData[i] >= 0x20 && textData[i] <= 0x7E {
					result.WriteByte(textData[i])
				} else if textData[i] == 0x0D || textData[i] == 0x0A {
					if result.Len() > 0 && result.String()[result.Len()-1] != '\n' {
						result.WriteString("\n")
					}
				}
				i++
			}
		}
	}

	return cleanExtractedText(result.String())
}

func extractAllTextFromBinary(data []byte) string {
	var result strings.Builder

	i := 0
	for i < len(data) {
		if data[i] >= 0x20 && data[i] <= 0x7E {
			start := i
			for i < len(data) && (data[i] >= 0x20 && data[i] <= 0x7E ||
				data[i] == 0x0A || data[i] == 0x0D || data[i] == 0x09) {
				i++
			}
			if i-start >= 2 {
				if result.Len() > 0 {
					result.WriteString("\n")
				}
				result.WriteString(string(data[start:i]))
			}
		} else if i+1 < len(data) && data[i] != 0x00 && data[i+1] != 0x00 {
			high := data[i]
			low := data[i+1]

			if high >= 0x4E && high <= 0x9F {
				code := uint16(low) | (uint16(high) << 8)
				char := rune(code)
				if char >= 0x4E00 && char <= 0x9FFF {
					result.WriteRune(char)
					i += 2
					continue
				}
			}

			if high >= 0x81 && high <= 0xFE && low >= 0x40 && low <= 0xFE && low != 0x7F {
				utf8Text, err := gbkToUTF8([]byte{high, low})
				if err == nil {
					result.WriteString(utf8Text)
				}
				i += 2
				continue
			}

			i++
		} else if i+1 < len(data) && data[i] == 0x00 && data[i+1] != 0x00 {
			code := uint16(data[i+1]) | (uint16(data[i]) << 8)
			if code >= 0x4E00 && code <= 0x9FFF {
				result.WriteRune(rune(code))
				i += 2
				continue
			}
			i++
		} else {
			i++
		}
	}

	return cleanExtractedText(result.String())
}

func extractUTF16Text(data []byte) string {
	var result strings.Builder
	i := 0

	for i < len(data)-1 {
		if data[i] == 0x00 && data[i+1] != 0x00 {
			start := i
			for i < len(data)-1 && data[i] == 0x00 && data[i+1] != 0x00 {
				if data[i+1] >= 0x20 && data[i+1] <= 0x7E {
					result.WriteByte(data[i+1])
				}
				i += 2
			}
			if i-start >= 4 {
				if result.Len() > 0 && result.String()[result.Len()-1] != '\n' {
					result.WriteString("\n")
				}
			}
		} else if data[i] != 0x00 && data[i+1] != 0x00 {
			high := data[i]
			low := data[i+1]
			if high >= 0x4E && high <= 0x9F {
				code := uint16(low) | (uint16(high) << 8)
				result.WriteRune(rune(code))
				i += 2
				continue
			} else if high >= 0x81 && high <= 0xFE && low >= 0x40 && low <= 0xFE && low != 0x7F {
				utf8Text, err := gbkToUTF8([]byte{high, low})
				if err == nil {
					result.WriteString(utf8Text)
				}
				i += 2
				continue
			}
			i++
		} else {
			i++
		}
	}

	return cleanExtractedText(result.String())
}

func extractTextFromXls(data []byte) (string, error) {
	return extractTextFromOLE2Fallback(data), nil
}

func extractRTFFromOLE2(data []byte) string {
	rtfStart := bytes.Index(data, []byte("{\\rtf"))
	if rtfStart == -1 {
		rtfStart = bytes.Index(data, []byte("{\\RTF"))
	}
	if rtfStart == -1 {
		return ""
	}

	rtfEnd := bytes.LastIndex(data[rtfStart:], []byte("}"))
	if rtfEnd == -1 {
		return ""
	}

	rtfData := data[rtfStart : rtfStart+rtfEnd+1]
	return parseRTF(string(rtfData))
}

var rtfTagRe = regexp.MustCompile(`\\[a-z]+[0-9]*\s?`)
var rtfGroupRe = regexp.MustCompile(`\{[^}]*\}`)
var rtfSpecialCharRe = regexp.MustCompile(`\\([nrtfb])`)
var rtfHexCharRe = regexp.MustCompile(`\\[uU]([0-9a-fA-F]{4})`)

func parseRTF(rtf string) string {
	rtf = strings.ReplaceAll(rtf, "\\{", "{")
	rtf = strings.ReplaceAll(rtf, "\\}", "}")
	rtf = strings.ReplaceAll(rtf, "\\\\", "\\")

	for {
		prev := rtf
		rtf = rtfGroupRe.ReplaceAllString(rtf, "")
		if rtf == prev {
			break
		}
	}

	rtf = rtfTagRe.ReplaceAllString(rtf, "")

	rtf = rtfSpecialCharRe.ReplaceAllStringFunc(rtf, func(match string) string {
		switch match[1] {
		case 'n':
			return "\n"
		case 'r':
			return "\r"
		case 't':
			return "\t"
		case 'f':
			return "\f"
		case 'b':
			return ""
		default:
			return ""
		}
	})

	rtf = rtfHexCharRe.ReplaceAllStringFunc(rtf, func(match string) string {
		if len(match) >= 6 {
			if code, err := strconv.ParseInt(match[2:], 16, 32); err == nil {
				return string(rune(code))
			}
		}
		return ""
	})

	return cleanExtractedText(rtf)
}

func extractTextFromWordDocument(data []byte) string {
	wordDocMarker := []byte("WordDocument")
	idx := bytes.Index(data, wordDocMarker)
	if idx == -1 {
		return ""
	}

	idx += len(wordDocMarker)
	for idx < len(data) && data[idx] == 0 {
		idx++
	}

	if idx >= len(data) {
		return ""
	}

	var result strings.Builder
	i := idx

	for i < len(data) {
		if data[i] == 0x0D || data[i] == 0x0A {
			if result.Len() > 0 && result.String()[result.Len()-1] != '\n' {
				result.WriteString("\n")
			}
			for i < len(data) && (data[i] == 0x0D || data[i] == 0x0A) {
				i++
			}
			continue
		}

		if data[i] >= 0x20 && data[i] <= 0x7E {
			result.WriteByte(data[i])
			i++
		} else if data[i] >= 0x80 && data[i] <= 0xFF && i+1 < len(data) {
			high := data[i]
			low := data[i+1]

			if high >= 0x81 && high <= 0xFE && low >= 0x40 && low <= 0xFE && low != 0x7F {
				utf8Text, err := gbkToUTF8([]byte{high, low})
				if err == nil {
					result.WriteString(utf8Text)
				} else {
					result.WriteByte(high)
					result.WriteByte(low)
				}
			} else if data[i+1] == 0x00 && data[i] != 0x00 {
				result.WriteByte(data[i])
			}
			i += 2
		} else if data[i] == 0x00 && i+1 < len(data) && data[i+1] != 0x00 {
			if data[i+1] >= 0x20 && data[i+1] <= 0x7E {
				result.WriteByte(data[i+1])
			}
			i += 2
		} else {
			i++
		}
	}

	return cleanExtractedText(result.String())
}

func extractTextFromOLE2Fallback(data []byte) string {
	var result strings.Builder

	i := 0
	for i < len(data) {
		if data[i] >= 0x20 && data[i] <= 0x7E {
			start := i
			for i < len(data) && (data[i] >= 0x20 && data[i] <= 0x7E ||
				data[i] == 0x0A || data[i] == 0x0D || data[i] == 0x09) {
				i++
			}
			if i-start > 3 {
				if result.Len() > 0 {
					result.WriteString("\n")
				}
				result.WriteString(string(data[start:i]))
			}
		} else if data[i] >= 0x80 && data[i] <= 0xFF && i+1 < len(data) {
			high := data[i]
			low := data[i+1]

			if high >= 0x81 && high <= 0xFE && low >= 0x40 && low <= 0xFE && low != 0x7F {
				utf8Text, err := gbkToUTF8([]byte{high, low})
				if err == nil {
					result.WriteString(utf8Text)
				}
			}
			i += 2
		} else if data[i] == 0x00 && i+1 < len(data) && data[i+1] != 0x00 && data[i+1] >= 0x20 && data[i+1] <= 0x7E {
			result.WriteByte(data[i+1])
			i += 2
		} else {
			i++
		}
	}

	return cleanExtractedText(result.String())
}

func gbkToUTF8(gbkData []byte) (string, error) {
	reader := transform.NewReader(bytes.NewReader(gbkData), simplifiedchinese.GBK.NewDecoder())
	utf8Data, err := io.ReadAll(reader)
	if err != nil {
		return "", err
	}
	return string(utf8Data), nil
}

func cleanExtractedText(text string) string {
	text = strings.ReplaceAll(text, "\x00", "")
	text = strings.ReplaceAll(text, "\x07", "")
	text = strings.ReplaceAll(text, "\x08", "")
	text = strings.ReplaceAll(text, "\x0b", "")
	text = strings.ReplaceAll(text, "\x0c", "")
	text = strings.ReplaceAll(text, "\x0e", "")
	text = strings.ReplaceAll(text, "\x0f", "")

	lines := strings.Split(text, "\n")
	var cleanedLines []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			cleanedLines = append(cleanedLines, line)
		}
	}

	return strings.Join(cleanedLines, "\n")
}

func (p *SensitiveWordPlugin) extractAnswerText(text string) string {
	if !p.isChatSession(text) {
		return text
	}

	var answerTexts []string

	if strings.Contains(text, "{") && strings.Contains(text, "}") {
		var jsonData interface{}
		if err := json.Unmarshal([]byte(text), &jsonData); err == nil {
			answerTexts = extractAnswerFromJSON(jsonData)
		} else {
			answerTexts = extractAnswerFromNonStandardJSON(text)
		}
	}

	if len(answerTexts) == 0 {
		answerTexts = extractAnswerFromText(text)
	}

	if len(answerTexts) > 0 {
		return strings.Join(answerTexts, "\n")
	}

	return text
}

var jsonFieldRe = regexp.MustCompile(`["'](answer|content|response|reply)["']\s*[:=]\s*(["']([^"']*)["']|(\[[^\]]*\])|(\{[^\}]*\})|(\d+)|([^\s,}\]]+))`)
var jsonStringRe = regexp.MustCompile(`["']([^"']*)["']`)

func extractAnswerFromNonStandardJSON(text string) []string {
	var result []string

	matches := jsonFieldRe.FindAllStringSubmatch(text, -1)
	for _, match := range matches {
		if len(match) >= 3 {
			fieldName := strings.ToLower(match[1])
			if fieldName == "answer" || fieldName == "content" || fieldName == "response" || fieldName == "reply" {
				var value string
				if len(match) >= 4 && match[4] != "" {
					value = match[4]
				} else if len(match) >= 3 && match[3] != "" {
					value = match[3]
				} else if len(match) >= 5 && match[5] != "" {
					value = match[5]
				} else if len(match) >= 6 && match[6] != "" {
					value = match[6]
				} else if len(match) >= 7 && match[7] != "" {
					value = match[7]
				}

				if value != "" && len(value) > 2 {
					if strings.HasPrefix(value, "{") && strings.HasSuffix(value, "}") {
						var nestedData interface{}
						if json.Unmarshal([]byte(value), &nestedData) == nil {
							result = append(result, extractAnswerFromJSON(nestedData)...)
						}
					} else if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
						var nestedData interface{}
						if json.Unmarshal([]byte(value), &nestedData) == nil {
							result = append(result, extractAnswerFromJSON(nestedData)...)
						}
					} else {
						result = append(result, value)
					}
				}
			}
		}
	}

	return result
}

func (p *SensitiveWordPlugin) isChatSession(text string) bool {
	chatIndicators := []string{
		"\"role\":", "\"role\": \"", "role:", "Role:",
		"\"answer\":", "\"answer\": \"", "answer:", "Answer:",
		"\"content\":", "\"content\": \"", "content:", "Content:",
		"assistant", "Assistant", "模型回答", "AI回答", "回复内容",
	}

	for _, indicator := range chatIndicators {
		if strings.Contains(text, indicator) {
			return true
		}
	}

	return false
}

func extractAnswerFromJSON(data interface{}) []string {
	var result []string

	switch v := data.(type) {
	case map[string]interface{}:
		for key, val := range v {
			lowerKey := strings.ToLower(key)
			if lowerKey == "answer" || lowerKey == "content" || lowerKey == "response" || lowerKey == "reply" {
				if str, ok := val.(string); ok {
					result = append(result, str)
				}
			} else if lowerKey == "messages" || lowerKey == "chat" || lowerKey == "conversation" {
				result = append(result, extractAnswerFromJSON(val)...)
			} else {
				result = append(result, extractAnswerFromJSON(val)...)
			}
		}
	case []interface{}:
		for _, item := range v {
			result = append(result, extractAnswerFromJSON(item)...)
		}
	}

	return result
}

func extractAnswerFromText(text string) []string {
	var result []string

	answerKeywords := []string{
		"answer:", "Answer:", "ANSWER:",
		"content:", "Content:", "CONTENT:",
		"response:", "Response:", "RESPONSE:",
		"reply:", "Reply:", "REPLY:",
		"assistant:", "Assistant:",
		"模型回答:", "AI回答:", "回复内容:",
		"assistant\n", "Assistant\n",
		"模型回答\n", "AI回答\n",
	}

	for _, keyword := range answerKeywords {
		parts := strings.Split(text, keyword)
		if len(parts) > 1 {
			for i := 1; i < len(parts); i++ {
				part := strings.TrimSpace(parts[i])
				if part != "" {
					result = append(result, part)
				}
			}
		}
	}

	return result
}

func parseDataURL(dataURL string) ([]byte, string, string) {
	parts := strings.SplitN(dataURL, ",", 2)
	if len(parts) != 2 {
		return nil, "", ""
	}

	header := parts[0]
	data := parts[1]

	var contentType string
	var fileName string

	headerParts := strings.Split(header, ";")
	for _, part := range headerParts {
		if strings.HasPrefix(part, "data:") {
			contentType = strings.TrimPrefix(part, "data:")
		} else if strings.HasPrefix(part, "filename=") {
			fileName = strings.TrimPrefix(part, "filename=")
			fileName = strings.Trim(fileName, "\"'")
		}
	}

	var decoded []byte
	var err error
	if strings.Contains(header, ";base64") {
		decoded, err = base64.StdEncoding.DecodeString(data)
		if err != nil {
			decoded, err = base64.URLEncoding.DecodeString(data)
		}
	} else {
		decoded = []byte(data)
	}

	if err != nil {
		return nil, contentType, fileName
	}

	return decoded, contentType, fileName
}

func decodeTextContent(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	data = removeUTF8BOM(data)

	if isUTF8(data) {
		return string(data)
	}

	return convertGBKToUTF8(data)
}

func removeUTF8BOM(data []byte) []byte {
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		return data[3:]
	}
	return data
}

func isUTF8(data []byte) bool {
	i := 0
	for i < len(data) {
		if (data[i] & 0x80) == 0x00 {
			i++
		} else if (data[i] & 0xE0) == 0xC0 {
			if i+1 >= len(data) {
				return false
			}
			if (data[i+1] & 0xC0) != 0x80 {
				return false
			}
			i += 2
		} else if (data[i] & 0xF0) == 0xE0 {
			if i+2 >= len(data) {
				return false
			}
			if (data[i+1]&0xC0) != 0x80 || (data[i+2]&0xC0) != 0x80 {
				return false
			}
			i += 3
		} else if (data[i] & 0xF8) == 0xF0 {
			if i+3 >= len(data) {
				return false
			}
			if (data[i+1]&0xC0) != 0x80 || (data[i+2]&0xC0) != 0x80 || (data[i+3]&0xC0) != 0x80 {
				return false
			}
			i += 4
		} else {
			return false
		}
	}
	return true
}

func convertGBKToUTF8(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	var result strings.Builder

	i := 0
	for i < len(data) {
		if data[i] < 0x80 {
			result.WriteByte(data[i])
			i++
		} else {
			if i+1 < len(data) {
				gbkCode := int(data[i])<<8 | int(data[i+1])
				utf8Str := gbkToUTF8Char(gbkCode)
				result.WriteString(utf8Str)
				i += 2
			} else {
				result.WriteByte(data[i])
				i++
			}
		}
	}

	return result.String()
}

func gbkToUTF8Char(gbkCode int) string {
	if gbkCode >= 0x8140 && gbkCode <= 0xFEFE {
		return string([]rune{rune(gbkCode + 0x8080)})
	}
	return string([]byte{byte(gbkCode >> 8), byte(gbkCode & 0xFF)})
}
