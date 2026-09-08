package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var Version = "0.1.0"

var rootCmd = &cobra.Command{
	Use:   "skillguard",
	Short: "Security scanner for AI agent skills",
	Long: `SkillGuard analyzes Markdown-based AI skill definitions for security vulnerabilities, dangerous permissions, and supply chain risks.

Version: ` + Version + `
Documentation: https://github.com/OSSAfrica/skillguard`,
	Version: Version,
	// Errors and usage are printed by Execute, which also decides the exit
	// code; without this cobra printed every error a second time and dumped
	// the usage block after a runtime failure.
	SilenceErrors: true,
	SilenceUsage:  true,
}

// Execute runs the CLI and maps its result to an exit code:
// 0 success, 1 skills below the threshold, 2 execution error.
func Execute() {
	err := rootCmd.Execute()
	if err == nil {
		return
	}

	if errors.Is(err, errSkillsFailed) {
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	os.Exit(2)
}
