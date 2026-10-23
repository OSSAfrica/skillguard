package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"skillguard/internal/assess"
)

func runAssessmentCLI(t *testing.T, args []string, stdin string) (assess.Response, string, error) {
	t.Helper()
	root := &cobra.Command{Use: "skillguard", SilenceErrors: true, SilenceUsage: true}
	root.AddCommand(newAssessCommand())
	root.SetArgs(append([]string{"assess"}, args...))
	root.SetIn(strings.NewReader(stdin))
	var out, diag bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&diag)
	err := root.Execute()
	var result assess.Response
	decoder := json.NewDecoder(&out)
	if parseErr := decoder.Decode(&result); parseErr != nil {
		t.Fatalf("stdout is not response JSON: %v %q (%v)", parseErr, out.String(), err)
	}
	if out.Len() != 0 && strings.TrimSpace(out.String()) != "" {
		t.Fatalf("extra stdout: %q", out.String())
	}
	return result, diag.String(), err
}

func TestAssessmentMachineOnlyErrors(t *testing.T) {
	for _, tt := range []struct {
		args  []string
		input string
		id    string
	}{
		{nil, `{}`, "SG_CLI_INVALID"},
		{[]string{"--unknown-SECRET"}, `{}`, "SG_CLI_INVALID"},
		{[]string{"--policy", "/nonexistent"}, `{"schema_version":1,"schema_version":2}`, "SG_REQUEST_INVALID"},
		{[]string{"--policy", "/nonexistent"}, strings.Repeat("a", assess.MaxBytes+1), "SG_REQUEST_INVALID"},
	} {
		result, stderr, err := runAssessmentCLI(t, tt.args, tt.input)
		code, ok := assessmentExitCode(err)
		if !ok || code != 2 || result.Status != "error" || result.Decision != "deny" || len(result.Rules) != 1 || result.Rules[0].ID != tt.id || stderr != "" {
			t.Fatalf("machine error contract: %+v, %v, %q", result, err, stderr)
		}
		if strings.Contains(result.Rules[0].Message, "SECRET") {
			t.Fatal("echoed malicious flag")
		}
	}
}

func TestAssessmentCLIReviewAndPolicyBoundary(t *testing.T) {
	dir := t.TempDir()
	policy := filepath.Join(t.TempDir(), "operator.json")
	data := `{"schema_version":1,"id":"operator","version":"1","max_age_seconds":60,"isolated_profiles":["sandbox-v1"],"reviewed_actions":[],"require_metadata":false,"verification":{"schema_version":1,"registries":[{"id":"pypi","ecosystem":"pypi","metadata_url":"https://pypi.org/pypi","install_url":"https://pypi.org/simple","packages":["requests"]}]}}`
	if err := os.WriteFile(policy, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	request := assess.Request{SchemaVersion: 1, TargetRoot: dir, CWD: dir, Action: assess.Action{Mode: "argv", Argv: []string{"pip", "install", "--only-binary=:all:", "--no-deps", "--index-url", "https://pypi.org/simple", "requests==2.32.3"}}, Environment: map[string]string{}, ContextProfile: "sandbox-v1", Inputs: []assess.Input{}}
	encoded, _ := json.Marshal(request)
	result, _, err := runAssessmentCLI(t, []string{"--policy", policy}, string(encoded))
	if code, ok := assessmentExitCode(err); !ok || code != 1 || result.Decision != "review" || result.Status != "complete" {
		t.Fatalf("review: %+v %v", result, err)
	}
	inside := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(inside, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	result, _, err = runAssessmentCLI(t, []string{"--policy", inside}, string(encoded))
	if result.Status != "error" || result.Decision != "deny" || result.Rules[0].ID != "SG_POLICY_INVALID" {
		t.Fatalf("target policy: %+v %v", result, err)
	}
}

func TestAssessmentExitMapping(t *testing.T) {
	for _, code := range []int{1, 2} {
		if got, ok := assessmentExitCode(assessmentExit{code}); !ok || got != code {
			t.Fatal("exit mapping")
		}
	}
	if _, ok := assessmentExitCode(errors.New("other")); ok {
		t.Fatal("changed scan error mapping")
	}
}
