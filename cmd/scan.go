package cmd

import (
	"encoding/json"
	"errors"
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
	Use:   "scan [path]",
	Short: "Scan AI skill definitions for security risks",
	Long:  `SkillGuard analyzes Markdown-based skill definitions for security vulnerabilities, dangerous permissions, and supply chain risks.`,
	RunE:  runScan,
}

func init() {
	scanCmd.Flags().StringVarP(&scanPath, "path", "p", "",
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

// errSkillsFailed reports skills scoring below the threshold. It is a distinct
// outcome from an execution error, and maps to exit code 1 rather than 2.
var errSkillsFailed = errors.New("one or more skills scored below the threshold")

func runScan(cmd *cobra.Command, args []string) error {
	cfg := loadConfig()

	// An explicit flag wins; otherwise the configured threshold applies.
	if !cmd.Flags().Changed("threshold") {
		threshold = cfg.Threshold
	}

	if err := validateThreshold(threshold); err != nil {
		return err
	}

	paths := resolveScanPaths(args, scanPath, cfg)

	report, warnings, err := scanPaths(paths, threshold)
	if err != nil {
		return err
	}

	if !quietMode {
		for _, w := range warnings {
			color.Yellow("Warning: %s", w)
		}
	}

	if report.TotalSkills == 0 {
		if !quietMode {
			color.Yellow("No skill files (*.md) found in paths: %v", paths)
		}

		return nil
	}

	if outputFile != "" {
		if err := writeJSONReport(outputFile, report); err != nil {
			return fmt.Errorf("failed to write report: %w", err)
		}

		color.Green("Report written to: %s", outputFile)
	}

	if !quietMode {
		printColoredReport(report)
	}

	return scanOutcome(report)
}

// scanOutcome turns a finished report into the command's result.
func scanOutcome(report *model.ScanReport) error {
	if report.Failed > 0 {
		return errSkillsFailed
	}

	return nil
}

// resolveScanPaths picks the paths to scan: positional arguments first, then
// --path, then the configured default.
func resolveScanPaths(args []string, flagPath string, cfg *Config) []string {
	if len(args) > 0 {
		paths := make([]string, 0, len(args))
		for _, arg := range args {
			paths = append(paths, splitPaths(arg)...)
		}

		return paths
	}

	if flagPath != "" {
		return splitPaths(flagPath)
	}

	return []string{cfg.DefaultPath}
}

// splitPaths splits the documented comma-separated form. A path that exists as
// written wins, since a filename may legitimately contain a comma.
func splitPaths(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	if !strings.Contains(raw, ",") {
		return []string{raw}
	}

	if _, err := os.Stat(expandPath(raw)); err == nil {
		return []string{raw}
	}

	var paths []string
	for _, part := range strings.Split(raw, ",") {
		if part = strings.TrimSpace(part); part != "" {
			paths = append(paths, part)
		}
	}

	return paths
}

// scanPaths analyses every skill and reference file under the given paths,
// returning the report and warnings for anything that had to be skipped.
func scanPaths(paths []string, threshold int) (*model.ScanReport, []string, error) {
	var (
		allFiles []parser.FoundFile
		warnings []string
	)

	for _, p := range paths {
		files, pathWarnings, err := parser.FindSkillFiles(expandPath(p))
		if err != nil {
			return nil, warnings, fmt.Errorf("failed to find skill files in %s: %w", p, err)
		}

		warnings = append(warnings, pathWarnings...)
		allFiles = append(allFiles, files...)
	}

	scorer := analyzer.NewScorer(threshold)
	report := &model.ScanReport{
		ScanTime:  time.Now().UTC(),
		Threshold: threshold,
		Results:   []model.AnalysisResult{},
	}

	for _, f := range allFiles {
		result, err := analyzeFile(scorer, f)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("skipped %s: %v", f.Path, err))
			continue
		}

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

	return report, warnings, nil
}

func analyzeFile(scorer *analyzer.Scorer, f parser.FoundFile) (*model.AnalysisResult, error) {
	if f.FileType == parser.FileTypeReference {
		body, err := parser.ExtractBodyOnly(f.Path)
		if err != nil {
			return nil, err
		}

		return scorer.AnalyzeReference(f.Path, body), nil
	}

	metadata, body, err := parser.ParseSkillFile(f.Path)
	if err != nil {
		return nil, err
	}

	return scorer.Analyze(f.Path, metadata, body), nil
}

func expandPath(path string) string {
	if len(path) > 1 && path[0] == '~' {
		if home := homeDir(); home != "" {
			return home + path[1:]
		}
	}

	return path
}

func printColoredReport(report *model.ScanReport) {
	fmt.Println()
	color.Cyan("╔══════════════════════════════════════════════════════════════════╗")
	color.Cyan("║                     SkillGuard Security Report                  ║")
	color.Cyan("╚══════════════════════════════════════════════════════════════════╝")
	fmt.Println()

	fmt.Printf("Scanned: %d skills | Threshold: %d | ", report.TotalSkills, report.Threshold)
	if report.Failed == 0 {
		color.Green("PASSED")
	} else {
		color.Red("FAILED")
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
	name := r.SkillName
	if r.IsReference {
		name = "[Reference] " + name
	}

	if r.Passed {
		color.Green("[PASS] %s", name)
	} else {
		color.Red("[FAIL] %s", name)
	}

	scoreColor := getScoreColor(r.OverallScore)
	_, err := scoreColor.Printf("  Score: %d/100", r.OverallScore)
	if err != nil {
		return
	}
	fmt.Println()
	fmt.Printf("  File: %s\n", r.FilePath)

	if r.CriticalCount > 0 {
		_, err := color.New(color.FgHiRed).Printf("  Critical findings: %d (automatic fail)\n", r.CriticalCount)
		if err != nil {
			return
		}
	}

	hasDetailedBreakdown := false
	for _, cs := range r.CategoryScores {
		if len(cs.Breakdown) > 0 {
			hasDetailedBreakdown = true
			break
		}
	}

	if len(r.CategoryScores) > 0 {
		fmt.Println("  Category Scores:")
		for _, cs := range r.CategoryScores {
			catColor := getCategoryScoreColor(cs.Score)
			_, err := catColor.Printf("    %s: %d/100", cs.Category, cs.Score)
			if err != nil {
				return
			}
			if verbose && len(cs.Breakdown) > 0 {
				checkWord := "checks"
				if len(cs.Breakdown) == 1 {
					checkWord = "check"
				}
				fmt.Printf(" (%d %s)\n", len(cs.Breakdown), checkWord)
			} else if cs.Findings > 0 {
				fmt.Printf(" (%d findings)\n", cs.Findings)
			} else {
				fmt.Println()
			}
		}
	}

	if verbose && hasDetailedBreakdown {
		fmt.Println("  Detailed Breakdown:")
		for _, cs := range r.CategoryScores {
			if len(cs.Breakdown) == 0 {
				continue
			}
			fmt.Printf("    %s:\n", cs.Category)
			for _, f := range cs.Breakdown {
				checkIcon := "OK"
				checkColor := color.New(color.FgGreen)
				if f.Deduction > 0 {
					checkIcon = "FAIL"
					checkColor = getSeverityColor(f.Severity)
				}
				_, err := checkColor.Printf("      [%s] %s", checkIcon, f.Description)
				if err != nil {
					return
				}
				if f.Deduction > 0 {
					fmt.Printf(" (-%d)\n", f.Deduction)
				} else {
					fmt.Println()
				}
			}
		}
	}

	if (verbose || !r.Passed) && len(r.Findings) > 0 {
		fmt.Println("  Findings:")
		for _, f := range r.Findings {
			severityIcon := getSeverityIcon(f.Severity)
			sevColor := getSeverityColor(f.Severity)
			_, err2 := sevColor.Printf("    %s %s", severityIcon, f.Description)
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
	case model.SeverityCritical:
		return color.New(color.FgHiRed)
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
	case model.SeverityCritical:
		return "[CRITICAL]"
	case model.SeverityHigh:
		return "[HIGH]"
	case model.SeverityMedium:
		return "[MEDIUM]"
	default:
		return "[LOW]"
	}
}

func writeJSONReport(path string, report *model.ScanReport) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}
