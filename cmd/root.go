package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "skillguard",
	Short: "",
	Long:  "",
	Run: func(cmd *cobra.Command, args []string) {
	},
}
