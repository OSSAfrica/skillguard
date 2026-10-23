package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"skillguard/internal/model"

	"github.com/spf13/cobra"
)

func TestRunScanStdinJSONAndSourceLabel(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	oldFormat, oldSource, oldQuiet, oldOutput, oldThreshold := format, stdinSource, quietMode, outputFile, threshold
	t.Cleanup(func() {
		format, stdinSource, quietMode, outputFile, threshold = oldFormat, oldSource, oldQuiet, oldOutput, oldThreshold
	})
	format, stdinSource, quietMode, outputFile = "json", "https://alice:source-secret@docs.example.org/llms.txt?token=source-query", false, ""
	var stdout, stderr bytes.Buffer
	command := &cobra.Command{}
	command.Flags().Int("threshold", 70, "")
	command.Flags().String("source", stdinSource, "")
	command.SetIn(strings.NewReader("npm install helper@1 --registry 'https://alice:registry-secret@registry.example.org/?token=registry-query'"))
	command.SetOut(&stdout)
	command.SetErr(&stderr)
	if err := runScan(command, []string{"-"}); err != nil {
		t.Fatal(err)
	}
	var report model.ScanReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("stdout is not JSON: %v, %s", err, stdout.String())
	}
	if len(report.Results) != 1 || report.Results[0].Extraction.Commands[0].Dependencies[0].Name != "helper" {
		t.Fatalf("bad report: %+v", report)
	}
	for _, secret := range []string{"alice", "source-secret", "source-query", "registry-secret", "registry-query"} {
		if strings.Contains(stdout.String(), secret) {
			t.Errorf("JSON leaks %q", secret)
		}
	}
}

func TestMarkdownIncludesEscapedExtractionAndGaps(t *testing.T) {
	input := filepath.Join(t.TempDir(), "llms.txt")
	writeSkill(t, input, "npm install helper@1\npip install -r missing.txt")
	report, _, err := scanPaths([]string{input}, 70)
	if err != nil {
		t.Fatal(err)
	}
	text := extractionMarkdown(report)
	if !strings.Contains(text, "helper") || !strings.Contains(text, "input_unavailable") || !strings.Contains(text, "lines 1") {
		t.Fatalf("extraction absent from Markdown: %s", text)
	}
	if got := markdownText("<script>[ignore](evil)|`code`"); strings.Contains(got, "<script>") || strings.Contains(got, "[ignore]") {
		t.Fatalf("untrusted Markdown was not escaped: %s", got)
	}
}

func TestRunScanWritesIncompleteReportFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	oldFormat, oldSource, oldQuiet, oldOutput, oldThreshold := format, stdinSource, quietMode, outputFile, threshold
	t.Cleanup(func() {
		format, stdinSource, quietMode, outputFile, threshold = oldFormat, oldSource, oldQuiet, oldOutput, oldThreshold
	})
	format, stdinSource, quietMode, outputFile = "json", "stdin", true, filepath.Join(dir, "report.json")
	command := &cobra.Command{}
	command.Flags().Int("threshold", 70, "")
	command.Flags().String("source", stdinSource, "")
	command.SetIn(strings.NewReader(strings.Repeat("x", 1<<20+1)))
	var stdout, stderr bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&stderr)
	if err := runScan(command, []string{"-"}); !errors.Is(err, errIncompleteScan) {
		t.Fatalf("incomplete scan = %v", err)
	}
	data, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatal(err)
	}
	var report model.ScanReport
	if err := json.Unmarshal(data, &report); err != nil || len(report.CoverageGaps) == 0 {
		t.Fatalf("missing coverage report: %s, %v", data, err)
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatal("quiet output emitted diagnostics")
	}
}
