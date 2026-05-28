package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"ai-sec-check/internal/config"
	"ai-sec-check/internal/gologger"
	"ai-sec-check/internal/plugin"
	"github.com/spf13/cobra"
)

var pluginsCmd = &cobra.Command{
	Use:   "plugins",
	Short: "List and manage scan plugins",
	Long:  `List all registered scan plugins, check their availability, and run individual plugin scans.`,
}

var pluginsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all registered plugins",
	Run: func(cmd *cobra.Command, args []string) {
		initPlugins()
		plugins := plugin.ListPlugins()
		if len(plugins) == 0 {
			fmt.Println("No plugins registered.")
			return
		}
		fmt.Printf("%-20s %-18s %-12s %s\n", "NAME", "CATEGORY", "AVAILABLE", "DESCRIPTION")
		fmt.Printf("%-20s %-18s %-12s %s\n", strings.Repeat("-", 19), strings.Repeat("-", 17), strings.Repeat("-", 10), strings.Repeat("-", 40))
		for _, p := range plugins {
			avail := "yes"
			if !p.IsAvailable() {
				avail = "no"
			}
			fmt.Printf("%-20s %-18s %-12s %s\n", p.Name(), p.Category(), avail, p.Description())
		}
	},
}

var pluginsScanCmd = &cobra.Command{
	Use:   "scan [plugin_name]",
	Short: "Run a specific plugin scan",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		initPlugins()
		pluginName := args[0]
		targetType, _ := cmd.Flags().GetString("type")
		targetValue, _ := cmd.Flags().GetString("target")
		outputJSON, _ := cmd.Flags().GetBool("json")

		if targetValue == "" {
			gologger.Fatalf("target is required, use --target")
		}
		if targetType == "" {
			targetType = "url"
		}

		p, ok := plugin.GetPlugin(pluginName)
		if !ok {
			gologger.Fatalf("plugin not found: %s", pluginName)
		}
		if !p.IsAvailable() {
			gologger.Fatalf("plugin not available: %s", pluginName)
		}

		target := plugin.ScanTarget{
			Type:  targetType,
			Value: targetValue,
		}
		if err := p.ValidateTarget(target); err != nil {
			gologger.Fatalf("invalid target: %v", err)
		}

		result, err := p.Scan(cmd.Context(), target)
		if err != nil {
			gologger.Fatalf("scan failed: %v", err)
		}

		if outputJSON {
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("\nScan Result: %s\n", result.Status)
			fmt.Printf("Plugin: %s | Category: %s | Target: %s\n", result.PluginName, result.Category, result.Target)
			fmt.Printf("Duration: %.2fs | Findings: %d\n", result.Duration, len(result.Findings))
			if result.Summary != "" {
				fmt.Printf("Summary: %s\n", result.Summary)
			}
			if len(result.Findings) > 0 {
				fmt.Printf("\n%-12s %-40s %s\n", "SEVERITY", "TITLE", "RULE ID")
				fmt.Printf("%-12s %-40s %s\n", strings.Repeat("-", 11), strings.Repeat("-", 39), strings.Repeat("-", 20))
				for _, f := range result.Findings {
					fmt.Printf("%-12s %-40s %s\n", f.Severity, f.Title, f.RuleID)
				}
			}
		}
	},
}

func init() {
	pluginsScanCmd.Flags().String("type", "url", "Target type: url, ip, cidr, file, text, api, mcp_config")
	pluginsScanCmd.Flags().String("target", "", "Target value (URL, IP, file path, etc.)")
	pluginsScanCmd.Flags().Bool("json", false, "Output result in JSON format")
	pluginsCmd.AddCommand(pluginsListCmd)
	pluginsCmd.AddCommand(pluginsScanCmd)
	rootCmd.AddCommand(pluginsCmd)
}

func initPlugins() {
	cfg, err := config.LoadConfig("configs/config.yaml")
	if err != nil {
		cfg = config.DefaultConfig()
	}
	_ = plugin.RegisterAllPlugins(cfg.GetPluginConfig)
}

func getHomeDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return home
}
