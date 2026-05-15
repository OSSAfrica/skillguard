package cmd

import (
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
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		_, err := fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		if err != nil {
			return
		}
		os.Exit(2)
	}
}
