package cmd

import (
	"os"
	"skillguard/internal/update"

	"github.com/spf13/cobra"
)

// Distribution is supplied by the release and container builds.
var Distribution = "source"

func newUpdateCommand() *cobra.Command {
	var check bool
	command := &cobra.Command{
		Use: "update", Short: "Update SkillGuard using its detected installation method",
		Long: "Check the latest stable release and update Homebrew or standalone release installations. Plugin, container, source and unknown installations receive instructions for their owning installer.",
		Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, args []string) error {
			executable, err := os.Executable()
			if err != nil {
				return err
			}
			return update.Execute(command.Context(), update.Options{Executable: executable, Version: Version, Distribution: Distribution, Check: check, Out: command.OutOrStdout()})
		},
	}
	command.Flags().BoolVar(&check, "check", false, "Report version and installation information without changing the installation")
	return command
}

func init() { rootCmd.AddCommand(newUpdateCommand()) }
