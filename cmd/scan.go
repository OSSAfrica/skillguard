package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"skillguard/internal/analyzer"
	"skillguard/internal/model"
	"skillguard/internal/parser"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	scanPath   string
	threshold  int
	outputFile string
	quietMode  bool
	verbose    bool
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan AI skill definitions for security risks",
	Long:  `SkillGuard analyzes Markdown-based skill definitions for security vulnerabilities, dangerous permissions, and supply chain risks.`,
	RunE:  runScan,
}

func init() {
	cfg := loadConfig()
	scanCmd.Flags().StringVarP(&scanPath, "path", "p", cfg.DefaultPath,
		"Path to scan (file, directory, or comma-separated paths)")
	scanCmd.Flags().IntVarP(&threshold, "threshold", "t", 70,
		"Minimum score to pass (0-100)")
	scanCmd.Flags().StringVarP(&outputFile, "output", "o", "",
		"Output JSON report to file (optional)")
	scanCmd.Flags().BoolVarP(&quietMode, "quiet", "q", false,
		"Minimal output - just pass/fail status")
	scanCmd.Flags().BoolVarP(&verbose, "verbose", "v", false,
		"Show all findings and detailed breakdown")

	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	cfg := loadConfig()
	paths := parsePaths(scanPath, cfg.DefaultPath)

	var allFiles []string
	for _, p := range paths {
		expandedPath := expandPath(p)
		files, err := parser.FindSkillFiles(expandedPath)
		if err != nil {
			return fmt.Errorf("failed to find skill files in %s: %w", p, err)
		}
		allFiles = append(allFiles, files...)
	}

	if len(allFiles) == 0 {
		if !quietMode {
			color.Yellow("No skill files (*.md) found in paths: %v", paths)
		}
		return nil
	}

	scorer := analyzer.NewScorer(threshold)
	report := model.ScanReport{
		ScanTime:  time.Now().UTC(),
		Threshold: threshold,
		Results:   []model.AnalysisResult{},
	}

	for _, file := range allFiles {
		metadata, body, err := parser.ParseSkillFile(file)
		if err != nil {
			if !quietMode {
				color.Red("Error parsing %s: %v", file, err)
			}
			continue
		}

		result := scorer.Analyze(file, metadata, body)
		report.Results = append(report.Results, *result)
	}

	report.TotalSkills = len(report.Results)
	for _, r := range report.Results {
		if r.Passed {
			report.Passed++
		} else {
			report.Failed++
		}
	}

	if outputFile != "" {
		if err := writeJSONReport(outputFile, &report); err != nil {
			return fmt.Errorf("failed to write report: %w", err)
		}
		color.Green("Report written to: %s", outputFile)
	}

	if !quietMode {
		printColoredReport(&report)
	}

	if report.Failed > 0 {
		os.Exit(1)
	}

	return nil
}

func expandPath(path string) string {
	if len(path) > 1 && path[0] == '~' {
		home := os.Getenv("HOME")
		if home != "" {
			return home + path[1:]
		}
	}
	return path
}

func parsePaths(input string, defaultPath string) []string {
	var paths []string
	for _, p := range strings.Split(input, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			paths = append(paths, p)
		}
	}
	if len(paths) == 0 {
		paths = []string{defaultPath}
	}
	return paths
}

func printColoredReport(report *model.ScanReport) {
	fmt.Println()
	color.Cyan("╔══════════════════════════════════════════════════════════════════╗")
	color.Cyan("║                     SkillGuard Security Report                  ║")
	color.Cyan("╚══════════════════════════════════════════════════════════════════╝")
	fmt.Println()

	fmt.Printf("Scanned: %d skills | Threshold: %d | ", report.TotalSkills, report.Threshold)
	if report.Failed == 0 {
		color.Green("PASSED ✓")
	} else {
		color.Red("FAILED ✗")
	}
	fmt.Println()
	fmt.Println(strings.Repeat("─", 70))

	for _, result := range report.Results {
		printSkillResult(&result, verbose)
	}

	fmt.Println(strings.Repeat("─", 70))
	fmt.Printf("Summary: %d passed, %d failed\n", report.Passed, report.Failed)
}

func printSkillResult(r *model.AnalysisResult, verbose bool) {
	if r.Passed {
		color.Green("✓ %s", r.SkillName)
	} else {
		color.Red("✗ %s", r.SkillName)
	}

	scoreColor := getScoreColor(r.OverallScore)
	_, err := scoreColor.Printf("  Score: %d/100", r.OverallScore)
	if err != nil {
		return
	}
	fmt.Println()
	fmt.Printf("  File: %s\n", r.FilePath)

	if len(r.CategoryScores) > 0 {
		fmt.Println("  Category Scores:")
		for _, cs := range r.CategoryScores {
			catColor := getCategoryScoreColor(cs.Score)
			_, err := catColor.Printf("    %s: %d/100", cs.Category, cs.Score)
			if err != nil {
				return
			}
			if cs.Findings > 0 {
				fmt.Printf(" (%d findings)\n", cs.Findings)
			} else {
				fmt.Println()
			}
		}
	}

	if !r.Passed && len(r.Findings) > 0 {
		fmt.Println("  Findings:")
		for _, f := range r.Findings {
			severityIcon := getSeverityIcon(f.Severity)
			sevColor := getSeverityColor(f.Severity)
			_, err2 := sevColor.Printf("    %s [%s] %s", severityIcon, f.Severity, f.Description)
			if err2 != nil {
				return
			}
			if f.Deduction > 0 {
				fmt.Printf(" (-%d)\n", f.Deduction)
			} else {
				fmt.Println()
			}
		}
	}
	fmt.Println()
}

func getCategoryScoreColor(score int) *color.Color {
	if score >= 80 {
		return color.New(color.FgGreen)
	} else if score >= 60 {
		return color.New(color.FgYellow)
	}
	return color.New(color.FgRed)
}

func getScoreColor(score int) *color.Color {
	if score >= 80 {
		return color.New(color.FgGreen)
	} else if score >= threshold {
		return color.New(color.FgYellow)
	}
	return color.New(color.FgRed)
}

func getSeverityColor(sev model.Severity) *color.Color {
	switch sev {
	case model.SeverityHigh:
		return color.New(color.FgRed)
	case model.SeverityMedium:
		return color.New(color.FgYellow)
	default:
		return color.New(color.FgBlue)
	}
}

func getSeverityIcon(sev model.Severity) string {
	switch sev {
	case model.SeverityHigh:
		return "🔴"
	case model.SeverityMedium:
		return "🟡"
	default:
		return "🔵"
	}
}

func writeJSONReport(path string, report *model.ScanReport) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
