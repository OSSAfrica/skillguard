package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"skillguard/internal/model"

	"github.com/spf13/cobra"
)

func TestVerificationRequiresExplicitOperatorPolicy(t *testing.T) {
	oldEnabled, oldPolicy := verifyReferences, verificationPolicy
	t.Cleanup(func() { verifyReferences, verificationPolicy = oldEnabled, oldPolicy })
	verifyReferences, verificationPolicy = false, ""
	if v, err := configuredVerifier(); err != nil || v != nil {
		t.Fatalf("static scan activated network checks: %v", err)
	}
	verificationPolicy = "untrusted-target/policy.json"
	if _, err := configuredVerifier(); err == nil {
		t.Fatal("policy used without explicit opt-in")
	}
	verifyReferences, verificationPolicy = true, ""
	if _, err := configuredVerifier(); err == nil {
		t.Fatal("network enabled without policy")
	}
}

func TestVerificationCLIReportAndIncompleteOutcome(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	oldEnabled, oldPolicy := verifyReferences, verificationPolicy
	oldFormat, oldQuiet, oldOutput, oldThreshold := format, quietMode, outputFile, threshold
	t.Cleanup(func() {
		verifyReferences, verificationPolicy = oldEnabled, oldPolicy
		format, quietMode, outputFile, threshold = oldFormat, oldQuiet, oldOutput, oldThreshold
	})
	policy := filepath.Join(dir, "trusted-policy.json")
	if err := os.WriteFile(policy, []byte(`{"schema_version":1,"registries":[{"id":"public","ecosystem":"npm","metadata_url":"https://127.0.0.1:1","install_url":"https://127.0.0.1:1","default":true,"packages":["public-helper"]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	verifyReferences, verificationPolicy = true, policy
	format, quietMode, outputFile = "json", false, ""
	command := &cobra.Command{}
	command.Flags().Int("threshold", 70, "")
	command.Flags().String("source", "stdin", "")
	command.SetContext(context.Background())
	command.SetIn(strings.NewReader("npm install company-private-helper@1.2.3"))
	var stdout, stderr bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&stderr)
	if err := runScan(command, []string{"-"}); !errors.Is(err, errVerificationIncomplete) {
		t.Fatalf("blocked check did not fail: %v", err)
	}
	var report model.ScanReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("incomplete report not JSON: %s, %v", stdout.String(), err)
	}
	p := report.Results[0].Verification.Packages[0]
	if p.State != "blocked" || p.Reason != "package_disclosure_not_authorized" || p.Identity != "unverified" {
		t.Fatalf("unexpected observation: %+v", p)
	}
	text := verificationMarkdown(&report)
	if !strings.Contains(text, "blocked") || !strings.Contains(text, "Identity") && !strings.Contains(text, "identity") {
		t.Fatalf("verification missing from Markdown: %s", text)
	}
}

func TestReferenceObservationExitSemantics(t *testing.T) {
	for _, tt := range []struct {
		state, version, malware, status string
		want                            error
	}{
		{"found", "found", "not_performed", "complete", nil},
		{"missing", "unknown", "not_performed", "complete", errReferencesFailed},
		{"found", "missing", "not_performed", "complete", errReferencesFailed},
		{"found", "found", "matched", "complete", errReferencesFailed},
		{"timeout", "unknown", "not_performed", "partial", errVerificationIncomplete},
	} {
		report := &model.ScanReport{Results: []model.AnalysisResult{{Verification: &model.ReferenceVerification{Status: tt.status, Packages: []model.PackageObservation{{State: tt.state, VersionState: tt.version, MalwareCheck: tt.malware, Identity: "unverified"}}}}}}
		if err := scanOutcome(report); !errors.Is(err, tt.want) {
			t.Errorf("state %s/%s: %v, want %v", tt.state, tt.version, err, tt.want)
		}
	}
}
