package cmd

import (
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/spf13/cobra"
	"skillguard/internal/assess"
)

type assessmentExit struct{ code int }

func (e assessmentExit) Error() string { return "action assessment withheld execution" }

func newAssessCommand() *cobra.Command {
	var policyPath string
	c := &cobra.Command{Use: "assess", Short: "Assess an exact proposed action; emit versioned JSON", Long: "Read one structured action request from stdin. Assessment never executes commands. Operator policy must be outside the target directory; an enforcing harness must protect policy and honor decisions."}
	c.Flags().StringVar(&policyPath, "policy", "", "Explicit protected operator action-policy JSON")
	emit := func(cmd *cobra.Command, r assess.Response) error {
		if err := json.NewEncoder(cmd.OutOrStdout()).Encode(r); err != nil {
			return err
		}
		if r.ExitCode() != 0 {
			return assessmentExit{r.ExitCode()}
		}
		return nil
	}
	c.SetFlagErrorFunc(func(cmd *cobra.Command, _ error) error {
		return emit(cmd, assess.ErrorResponse(Version, "SG_CLI_INVALID", time.Now()))
	})
	c.RunE = func(cmd *cobra.Command, args []string) error {
		failure := func(code string) error { return emit(cmd, assess.ErrorResponse(Version, code, time.Now())) }
		if len(args) != 0 || policyPath == "" {
			return failure("SG_CLI_INVALID")
		}
		data, err := io.ReadAll(io.LimitReader(cmd.InOrStdin(), assess.MaxBytes+1))
		if err != nil {
			return failure("SG_REQUEST_UNREADABLE")
		}
		request, err := assess.DecodeRequest(data)
		if err != nil {
			return failure("SG_REQUEST_INVALID")
		}
		policy, err := assess.LoadPolicy(policyPath, request.TargetRoot)
		if err != nil {
			return failure("SG_POLICY_INVALID")
		}
		return emit(cmd, assess.Evaluate(cmd.Context(), request, policy, assess.Options{EngineVersion: Version}))
	}
	return c
}

func init() { rootCmd.AddCommand(newAssessCommand()) }

func assessmentExitCode(err error) (int, bool) {
	var result assessmentExit
	if errors.As(err, &result) {
		return result.code, true
	}
	return 0, false
}
