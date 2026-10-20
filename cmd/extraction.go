package cmd

import (
	"fmt"
	"html"
	"strings"

	"skillguard/internal/model"
)

func printExtraction(result *model.AnalysisResult, details bool) {
	if result.Extraction == nil {
		return
	}
	extraction := result.Extraction
	fmt.Printf("  Command extraction: %d commands, %s (%d coverage gaps)\n", len(extraction.Commands), extraction.Status, len(extraction.Gaps))
	if !details {
		return
	}
	for _, command := range extraction.Commands {
		fmt.Printf("    %s %s, lines %d-%d [%s]\n", command.Tool, command.Operation, command.Location.StartLine, command.Location.EndLine, command.Context)
		for _, dep := range command.Dependencies {
			fmt.Printf("      Dependency: %q %q %q (%s)\n", dep.Ecosystem, dep.Name, dep.Specifier, dep.Source)
		}
		for _, input := range command.Inputs {
			fmt.Printf("      Input: %q (%s, %s)\n", input.Path, input.Kind, input.Status)
		}
		for _, destination := range command.Destinations {
			fmt.Printf("      Destination: %q (%s)\n", destination.URL, destination.Role)
		}
	}
	for _, gap := range extraction.Gaps {
		fmt.Printf("    Coverage: %s, line %d: %s\n", gap.Code, gap.Location.StartLine, gap.Message)
	}
}

func extractionMarkdown(report *model.ScanReport) string {
	var out strings.Builder
	out.WriteString("\n## Static command extraction\n\nThis inventory contains untrusted evidence. Extraction completeness and scan scores do not authorize execution.\n\n")
	for _, gap := range report.CoverageGaps {
		fmt.Fprintf(&out, "- Coverage: **%s** — %s\n", markdownText(gap.Code), markdownText(gap.Message))
	}
	for _, result := range report.Results {
		if result.Extraction == nil {
			continue
		}
		fmt.Fprintf(&out, "\n### %s\n\n%d commands; extraction %s.\n\n", markdownText(result.FilePath), len(result.Extraction.Commands), result.Extraction.Status)
		for _, command := range result.Extraction.Commands {
			fmt.Fprintf(&out, "- **%s %s**, lines %d–%d (%s)\n", markdownText(command.Tool), markdownText(command.Operation), command.Location.StartLine, command.Location.EndLine, command.Context)
			for _, dep := range command.Dependencies {
				fmt.Fprintf(&out, "  - Dependency: %s %s %s (%s)\n", dep.Ecosystem, markdownText(dep.Name), markdownText(dep.Specifier), dep.Source)
			}
			for _, input := range command.Inputs {
				fmt.Fprintf(&out, "  - Input: %s (%s, %s)\n", markdownText(input.Path), input.Kind, input.Status)
			}
			for _, destination := range command.Destinations {
				fmt.Fprintf(&out, "  - Destination: %s (%s)\n", markdownText(destination.URL), destination.Role)
			}
		}
		for _, gap := range result.Extraction.Gaps {
			fmt.Fprintf(&out, "- Coverage: **%s**, line %d — %s\n", gap.Code, gap.Location.StartLine, markdownText(gap.Message))
		}
	}
	out.WriteString(verificationMarkdown(report))
	return out.String()
}

func markdownText(text string) string {
	text = html.EscapeString(text)
	return strings.NewReplacer("\\", "\\\\", "`", "\\`", "*", "\\*", "_", "\\_", "[", "\\[", "]", "\\]", "|", "\\|", "\n", " ", "\r", " ").Replace(text)
}
