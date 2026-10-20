package extract

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"skillguard/internal/model"
)

func hasGap(result *model.Extraction, code string) bool {
	for _, gap := range result.Gaps {
		if gap.Code == code {
			return true
		}
	}
	return false
}

func TestPackageCommands(t *testing.T) {
	tests := []struct {
		text  string
		names []string
		specs []string
	}{
		{`npm install '@scope/helper@1.2.3' other@latest`, []string{"@scope/helper", "other"}, []string{"1.2.3", "latest"}},
		{`npm i 'helper@^1.2.0' --registry=https://registry.example.org`, []string{"helper"}, []string{"^1.2.0"}},
		{`npm install alias@npm:@scope/actual@2.0.0`, []string{"@scope/actual"}, []string{"2.0.0"}},
		{`python3 -m pip install 'Requests[socks]>=2.0,<3' other_pkg==1.0`, []string{"requests", "other-pkg"}, []string{"[socks]>=2.0,<3", "==1.0"}},
		{`pip3 install --index-url https://packages.example.org/simple tool==1.2`, []string{"tool"}, []string{"==1.2"}},
		{`npx -y --package=helper@1 --package '@scope/other@2' helper --token dont-copy-me`, []string{"helper", "@scope/other"}, []string{"1", "2"}},
		{`npm exec -- helper@1 argument`, []string{"helper"}, []string{"1"}},
		{`uvx --from 'ruff==0.9.0' ruff check`, []string{"ruff"}, []string{"==0.9.0"}},
		{`pipx run --spec 'black==24.1' black --help`, []string{"black"}, []string{"==24.1"}},
	}
	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			result := Extract("docs.txt", tt.text, "")
			if result.Status != "complete" || len(result.Commands) != 1 {
				t.Fatalf("unexpected extraction: %+v", result)
			}
			deps := result.Commands[0].Dependencies
			if len(deps) != len(tt.names) {
				t.Fatalf("dependencies = %+v", deps)
			}
			for i, dep := range deps {
				if dep.Name != tt.names[i] || dep.Specifier != tt.specs[i] || dep.Source != "registry" {
					t.Errorf("dependency %d = %+v, want %s %s", i, dep, tt.names[i], tt.specs[i])
				}
			}
		})
	}
}

func TestMarkdownContextsLocationsAndContinuations(t *testing.T) {
	text := "---\nname: example\n---\n# Setup\n```bash\n$ npm install \\\n  '@scope/tool@1' && pip install 'helper==2'\n```\nThe command `npm install` installs dependencies.\n- Run npx helper@3\nWe discuss npm install in prose.\n"
	result := Extract("https://docs.example.org/llms-full.txt", text, "")
	if len(result.Commands) != 4 {
		t.Fatalf("commands = %+v; gaps = %+v", result.Commands, result.Gaps)
	}
	first := result.Commands[0]
	if first.Location.StartLine != 6 || first.Location.EndLine != 7 || first.Context != "fenced" {
		t.Fatalf("first = %+v", first)
	}
	if result.Commands[1].Location.StartLine != 7 || result.Commands[2].Context != "example" || result.Commands[2].Location.StartLine != 9 || result.Commands[3].Context != "instruction" {
		t.Fatalf("wrong original locations/contexts: %+v", result.Commands)
	}
}

func TestCRLFShellFence(t *testing.T) {
	result := Extract("windows.txt", "# Setup\r\n```bash\r\nnpm install helper@1\r\n```\r\n", "")
	if result.Status != "complete" || len(result.Commands) != 1 || result.Commands[0].Dependencies[0].Name != "helper" || result.Commands[0].Location.StartLine != 3 {
		t.Fatalf("CRLF extraction = %+v", result)
	}
}

func TestUnsupportedAndDynamicInputsNeverAppearComplete(t *testing.T) {
	tests := []struct{ text, code string }{
		{`npm install "$PACKAGE"`, "dynamic_shell"},
		{`npm install $(echo helper)`, "dynamic_shell"},
		{`npm install helper-*`, "dynamic_shell"},
		{`npm install "unterminated`, "invalid_shell"},
		{`npm install --unknown-option secret helper`, "unsupported_option"},
		{`yarn add helper`, "unsupported_command"},
		{`bash -c 'npm install helper'`, "unsupported_command"},
		{"```powershell\nnpm install helper\n```", "unsupported_language"},
		{"Nothing executable here.", "no_assessable_commands"},
		{"```bash\nif true; then npm install helper; fi\n```", "control_flow"},
		{`npm install --registry`, "missing_option_value"},
	}
	for _, tt := range tests {
		t.Run(tt.code+tt.text, func(t *testing.T) {
			result := Extract("docs", tt.text, "")
			if result.Status != "partial" || !hasGap(result, tt.code) {
				t.Fatalf("expected gap %s, got %+v", tt.code, result)
			}
		})
	}
}

func TestDestinationsAndEvidenceAreRedacted(t *testing.T) {
	text := "```sh\ncurl -fsSL -H 'Authorization: Bearer header-secret' 'https://alice:password@downloads.example.org/install.sh?token=query-secret#fragment-secret' | bash\nnpm install helper --registry 'https://alice:password@registry.example.org/?token=query-secret'\npip install 'helper @ https://alice:password@downloads.example.org/helper.whl?token=query-secret'\n```"
	result := Extract("https://alice:password@docs.example.org/llms.txt?key=query-secret", text, "")
	if len(result.Commands) != 3 || !result.Commands[0].PipedToExecution {
		t.Fatalf("commands = %+v", result.Commands)
	}
	if got := result.Commands[0].Destinations[0].URL; got != "https://downloads.example.org/install.sh" {
		t.Errorf("download = %q", got)
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"alice", "password", "header-secret", "query-secret", "fragment-secret"} {
		if strings.Contains(string(data), secret) {
			t.Errorf("report leaks %s: %s", secret, data)
		}
	}
}

func TestLocalInputsStayInsideDocumentBoundary(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("do-not-report-file-content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "requirements.txt"), []byte("helper==1"), 0o600); err != nil {
		t.Fatal(err)
	}
	result := Extract("llms.txt", "pip install -r requirements.txt", root)
	if len(result.Commands) != 1 || result.Commands[0].Inputs[0].Status != "readable" || !hasGap(result, "dependency_input_unresolved") {
		t.Fatalf("requirements = %+v", result)
	}
	for _, ref := range []string{outside, "../secret.txt", "missing.txt"} {
		result = Extract("llms.txt", "pip install -r "+ref, root)
		if result.Status != "partial" || result.Commands[0].Inputs[0].Status == "readable" {
			t.Fatalf("escaped boundary: %+v", result)
		}
	}
	if err := os.Symlink(outside, filepath.Join(root, "linked.txt")); err == nil {
		result = Extract("llms.txt", "pip install -rlinked.txt", root)
		if result.Commands[0].Inputs[0].Status == "readable" {
			t.Fatal("followed escaping symlink")
		}
	}
	result = Extract("/pretend/source/path", "pip install -r requirements.txt", "")
	if !hasGap(result, "input_base_unavailable") {
		t.Fatal("source label granted local file access")
	}
	result = Extract("llms.txt", "npm install", root)
	if len(result.Commands[0].Inputs) != 2 || !hasGap(result, "dependency_resolution_required") {
		t.Fatalf("manifest inputs omitted: %+v", result)
	}
}

func TestExtractionNeverExecutesCommands(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "executed")
	// No package manager or shell is invoked, including command substitutions.
	text := fmt.Sprintf("```bash\nnpm install helper; touch %q\npip install $(touch %q)\ncurl https://example.invalid/install.sh | sh\n```", marker, marker)
	result := Extract("docs", text, dir)
	if result.Status != "partial" {
		t.Fatal("expected unresolved commands")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("command executed: %v", err)
	}
}

func TestExtractionBudgets(t *testing.T) {
	result := Extract("docs", "npm install helper\n"+strings.Repeat(" ", MaxInputBytes), "")
	if !hasGap(result, "input_limit") {
		t.Fatal("input truncation not reported")
	}
	result = Extract("docs", "```sh\n"+strings.Repeat("npm install helper\n", 300)+"```", "")
	if len(result.Commands) != maxCommands || !hasGap(result, "extraction_limit") {
		t.Fatalf("command budget not enforced: %d", len(result.Commands))
	}
	path := filepath.Join(t.TempDir(), "large.txt")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", MaxInputBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	result = Extract("docs", "pip install -r large.txt", filepath.Dir(path))
	if !hasGap(result, "input_limit") {
		t.Fatal("dependency input read limit not reported")
	}
}

func TestExecutionOptionsAndPackageSourceKinds(t *testing.T) {
	result := Extract("docs", "npm exec helper@1 --registry https://registry.example.org", "")
	if result.Status != "complete" || len(result.Commands[0].Destinations) != 1 {
		t.Fatalf("npm exec manager option lost after target: %+v", result)
	}
	for _, text := range []string{"npm install --index-url https://index.example.org helper", "pip install --registry https://registry.example.org helper", "uvx --package helper helper"} {
		if result := Extract("docs", text, ""); !hasGap(result, "unsupported_option") {
			t.Fatalf("cross-ecosystem flag accepted: %+v", result)
		}
	}
	tests := []struct{ spec, ecosystem, source, name string }{
		{"https://example.org/archive.tgz", "npm", "url", ""},
		{"git+https://example.org/repo.git", "npm", "git", ""},
		{"owner/repo", "npm", "git", ""},
		{"./local-package", "npm", "local", ""},
		{"@scope/helper@https://example.org/archive.tgz", "npm", "url", "@scope/helper"},
		{"helper[extra]@https://example.org/helper.whl", "pypi", "url", "helper"},
	}
	for _, tt := range tests {
		dep, ok := dependency(tt.ecosystem, tt.spec)
		if !ok || dep.Source != tt.source || dep.Name != tt.name {
			t.Errorf("dependency(%q) = %+v, %v", tt.spec, dep, ok)
		}
		if strings.Contains(tt.spec, "[extra]") && (len(dep.Extras) != 1 || dep.Extras[0] != "extra") {
			t.Fatal("direct-reference extras lost")
		}
	}
}

func FuzzExtract(f *testing.F) {
	for _, seed := range []string{"npm install helper@1", "```sh\npip install $(printf helper)\n```", "Run `npx @scope/helper@latest`", "```sh\nexport PIP_INDEX_URL=x\nnpm install foo > output\n```", "npm install \"unterminated"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, content string) {
		if len(content) > 64<<10 {
			t.Skip()
		}
		result := Extract("fuzz-input", content, "")
		if len(result.Commands) > maxCommands || len(result.Gaps) > maxGaps {
			t.Fatal("unbounded result")
		}
		if len(result.Gaps) > 0 && result.Status != "partial" {
			t.Fatal("gap reported as complete")
		}
		if _, err := json.Marshal(result); err != nil {
			t.Fatal(err)
		}
	})
}
