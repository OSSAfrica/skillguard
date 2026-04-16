package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var version = "0.1.0"

var rootCmd = &cobra.Command{
	Use:   "skillguard",
	Short: "Security scanner for AI agent skills",
	Long: `SkillGuard analyzes Markdown-based AI skill definitions for security vulnerabilities, dangerous permissions, and supply chain risks.

Version: ` + version + `
Documentation: https://github.com/OSSAfrica/skillguard`,
	Version: version,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}
}
