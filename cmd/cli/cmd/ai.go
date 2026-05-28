package cmd

import (
	"fmt"
	"os"

	"ai-sec-check/internal/ai"
	"ai-sec-check/internal/config"
	"ai-sec-check/internal/gologger"
	"ai-sec-check/internal/plugin"
	"ai-sec-check/internal/storage"
	"ai-sec-check/pkg/database"
	"github.com/spf13/cobra"
)

var aiCmd = &cobra.Command{
	Use:   "ai",
	Short: "AI assistant for security analysis",
	Long:  `Use AI to analyze scan results, generate reports, suggest fixes, and chat about security topics.`,
}

var aiStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show AI assistant status",
	Run: func(cmd *cobra.Command, args []string) {
		mgr := initAIManager()
		enabled := mgr.IsAIEnabled()
		available := mgr.IsAvailable()
		fmt.Printf("AI Assistant Status:\n")
		fmt.Printf("  Enabled:   %v\n", enabled)
		fmt.Printf("  Available: %v\n", available)
		fmt.Printf("  Model:     %s\n", mgr.GetModelName())
		fmt.Printf("  Base URL:  %s\n", mgr.GetBaseURL())
		if !enabled {
			fmt.Printf("\nAI is disabled. Enable it in configs/config.yaml or use: ai config --enabled --base-url <url> --model <model>")
		}
	},
}

var aiAnalyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "Analyze scan results with AI",
	Run: func(cmd *cobra.Command, args []string) {
		mgr := initAIManager()
		category, _ := cmd.Flags().GetString("category")
		limit, _ := cmd.Flags().GetInt("limit")

		results := collectResultsForAI(category, limit)
		if len(results) == 0 {
			gologger.Fatalf("no scan results found. Run a scan first.")
		}

		fmt.Printf("Analyzing %d scan result(s)...\n\n", len(results))
		analysis, err := mgr.Analyze(results)
		if err != nil {
			gologger.Fatalf("analysis failed: %v", err)
		}
		fmt.Println(analysis)
	},
}

var aiReportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate security report with AI",
	Run: func(cmd *cobra.Command, args []string) {
		mgr := initAIManager()
		category, _ := cmd.Flags().GetString("category")
		format, _ := cmd.Flags().GetString("format")
		outputPath, _ := cmd.Flags().GetString("output")
		limit, _ := cmd.Flags().GetInt("limit")

		results := collectResultsForAI(category, limit)
		if len(results) == 0 {
			gologger.Fatalf("no scan results found. Run a scan first.")
		}

		fmt.Printf("Generating %s report for %d scan result(s)...\n\n", format, len(results))
		report, err := mgr.GenerateReport(results, format)
		if err != nil {
			gologger.Fatalf("report generation failed: %v", err)
		}

		if outputPath != "" {
			if err := os.WriteFile(outputPath, []byte(report), 0644); err != nil {
				gologger.Fatalf("failed to write report: %v", err)
			}
			fmt.Printf("Report saved to: %s\n", outputPath)
		} else {
			fmt.Println(report)
		}
	},
}

var aiSuggestCmd = &cobra.Command{
	Use:   "suggest",
	Short: "Get AI fix suggestion for a finding",
	Run: func(cmd *cobra.Command, args []string) {
		mgr := initAIManager()
		title, _ := cmd.Flags().GetString("title")
		severity, _ := cmd.Flags().GetString("severity")
		desc, _ := cmd.Flags().GetString("description")

		if title == "" {
			gologger.Fatalf("--title is required")
		}

		finding := plugin.Finding{
			Severity:    severity,
			Title:       title,
			Description: desc,
		}

		fmt.Printf("Getting fix suggestion for: %s\n\n", title)
		suggestion, err := mgr.SuggestFix(finding)
		if err != nil {
			gologger.Fatalf("suggestion failed: %v", err)
		}
		fmt.Println(suggestion)
	},
}

var aiChatCmd = &cobra.Command{
	Use:   "chat [question]",
	Short: "Chat with AI security assistant",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		mgr := initAIManager()
		question := args[0]
		context, _ := cmd.Flags().GetString("context")

		answer, err := mgr.Chat(question, context)
		if err != nil {
			gologger.Fatalf("chat failed: %v", err)
		}
		fmt.Println(answer)
	},
}

var aiConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Configure AI assistant settings",
	Run: func(cmd *cobra.Command, args []string) {
		enabled, _ := cmd.Flags().GetBool("enabled")
		baseURL, _ := cmd.Flags().GetString("base-url")
		apiKey, _ := cmd.Flags().GetString("api-key")
		model, _ := cmd.Flags().GetString("model")

		appCfg, err := config.LoadConfig("configs/config.yaml")
		if err != nil {
			appCfg = config.DefaultConfig()
		}

		if cmd.Flags().Changed("enabled") {
			appCfg.AI.Enabled = enabled
		}
		if cmd.Flags().Changed("base-url") {
			appCfg.AI.BaseURL = baseURL
		}
		if cmd.Flags().Changed("api-key") {
			appCfg.AI.APIKey = apiKey
		}
		if cmd.Flags().Changed("model") {
			appCfg.AI.Model = model
		}

		fmt.Printf("AI Configuration Updated:\n")
		fmt.Printf("  Enabled:  %v\n", appCfg.AI.Enabled)
		fmt.Printf("  Base URL: %s\n", appCfg.AI.BaseURL)
		fmt.Printf("  Model:    %s\n", appCfg.AI.Model)
		fmt.Printf("  API Key:  %s\n", maskKey(appCfg.AI.APIKey))
	},
}

func init() {
	aiAnalyzeCmd.Flags().String("category", "", "Filter by scan category")
	aiAnalyzeCmd.Flags().Int("limit", 20, "Max results to analyze")

	aiReportCmd.Flags().String("category", "", "Filter by scan category")
	aiReportCmd.Flags().String("format", "markdown", "Report format: markdown, html")
	aiReportCmd.Flags().String("output", "", "Output file path (default: stdout)")
	aiReportCmd.Flags().Int("limit", 20, "Max results to include")

	aiSuggestCmd.Flags().String("title", "", "Finding title")
	aiSuggestCmd.Flags().String("severity", "high", "Finding severity")
	aiSuggestCmd.Flags().String("description", "", "Finding description")

	aiChatCmd.Flags().String("context", "", "Additional context for the question")

	aiConfigCmd.Flags().Bool("enabled", false, "Enable/disable AI")
	aiConfigCmd.Flags().String("base-url", "", "OpenAI-compatible API base URL")
	aiConfigCmd.Flags().String("api-key", "", "API key")
	aiConfigCmd.Flags().String("model", "", "Model name")

	aiCmd.AddCommand(aiStatusCmd)
	aiCmd.AddCommand(aiAnalyzeCmd)
	aiCmd.AddCommand(aiReportCmd)
	aiCmd.AddCommand(aiSuggestCmd)
	aiCmd.AddCommand(aiChatCmd)
	aiCmd.AddCommand(aiConfigCmd)
	rootCmd.AddCommand(aiCmd)
}

func initAIManager() *ai.Manager {
	cfg, err := config.LoadConfig("configs/config.yaml")
	if err != nil {
		cfg = config.DefaultConfig()
	}
	return ai.NewManager(cfg.GetAIConfig())
}

func collectResultsForAI(category string, limit int) []*plugin.ScanResult {
	dbConfig := database.LoadConfigFromEnv()
	db, err := database.InitDB(dbConfig)
	if err != nil {
		return nil
	}
	store := storage.NewScanResultStore(db)

	if limit <= 0 {
		limit = 20
	}
	if category != "" {
		results, _ := store.ListByCategory(category, limit)
		return results
	}
	results, _ := store.List(limit)
	return results
}

func maskKey(key string) string {
	if len(key) <= 8 {
		return "****"
	}
	return key[:4] + "****" + key[len(key)-4:]
}
