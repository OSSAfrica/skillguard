package parser

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseAllowedTools(t *testing.T) {
	tests := []struct {
		name string
		input interface{}
		want  []string
	}{
		{
			name:  "nil input",
			input: nil,
			want:  nil,
		},
		{
			name:  "empty string",
			input: "",
			want:  nil,
		},
		{
			name:  "single tool string",
			input: "fetch",
			want:  []string{"fetch"},
		},
		{
			name:  "comma-separated tools",
			input: "fetch, read, write",
			want:  []string{"fetch", "read", "write"},
		},
		{
			name:  "slice of strings",
			input: []interface{}{"fetch", "read", "write"},
			want:  []string{"fetch", "read", "write"},
		},
		{
			name:  "slice with non-strings",
			input: []interface{}{"fetch", 42, "read"},
			want:  []string{"fetch", "read"},
		},
		{
			name:  "non-string non-slice",
			input: 123,
			want:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseAllowedTools(tt.input)
			if len(got) != len(tt.want) {
				t.Errorf("parseAllowedTools() = %v, want %v", got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("parseAllowedTools()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestExtractFrontmatter(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		wantErr     bool
		wantName    string
		wantBody    string
	}{
		{
			name: "valid frontmatter",
			content: `---
name: test-skill
description: A test skill
---
This is the body content.`,
			wantErr:  false,
			wantName: "test-skill",
			wantBody: "This is the body content.",
		},
		{
			name: "no frontmatter",
			content: `# Just a heading
No frontmatter here.`,
			wantErr: true,
		},
		{
			name: "unclosed frontmatter",
			content: `---
name: broken
body starts but never closes`,
			wantErr: true,
		},
		{
			name: "invalid YAML",
			content: `---
name: [unclosed
---
Body`,
			wantErr: true,
		},
		{
			name: "empty body",
			content: `---
name: no-body
---`,
			wantErr:  false,
			wantName: "no-body",
			wantBody: "",
		},
		{
			name: "with array fields",
			content: `---
name: array-skill
triggers:
  - test
  - example
allowed-tools:
  - fetch
  - read
---
Body content.`,
			wantErr:  false,
			wantName: "array-skill",
			wantBody: "Body content.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fm, body, err := extractFrontmatter(tt.content)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if fm.Name != tt.wantName {
				t.Errorf("name = %q, want %q", fm.Name, tt.wantName)
			}
			if body != tt.wantBody {
				t.Errorf("body = %q, want %q", body, tt.wantBody)
			}
		})
	}
}

func TestParseSkillFile(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name        string
		content     string
		wantName    string
		wantErr     bool
	}{
		{
			name: "valid skill file",
			content: `---
name: valid-skill
description: A valid skill
source: https://github.com/example/skill
triggers:
  - test
---
Safe body content here.`,
			wantName: "valid-skill",
			wantErr:  false,
		},
		{
			name: "missing name uses filename",
			content: `---
description: No name skill
---
Body`,
			wantName: "test-file",
			wantErr:  false,
		},
		{
			name: "nonexistent file",
			content: "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var path string
			if tt.wantErr && tt.content == "" {
				path = filepath.Join(tmpDir, "nonexistent.md")
			} else {
				path = filepath.Join(tmpDir, "test-file.md")
				if err := os.WriteFile(path, []byte(tt.content), 0644); err != nil {
					t.Fatal(err)
				}
			}

			metadata, body, err := ParseSkillFile(path)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if metadata.Name != tt.wantName {
				t.Errorf("metadata.Name = %q, want %q", metadata.Name, tt.wantName)
			}
			if body == "" {
				t.Error("expected non-empty body")
			}
		})
	}
}

func TestExtractBodyOnly(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name     string
		content  string
		wantBody string
		wantErr  bool
	}{
		{
			name: "file with frontmatter",
			content: `---
name: test
---
Body content`,
			wantBody: "Body content",
			wantErr:  false,
		},
		{
			name:     "file without frontmatter",
			content:  `# Just a heading`,
			wantBody: `# Just a heading`,
			wantErr:  false,
		},
		{
			name: "empty body with frontmatter",
			content: `---
name: test
---`,
			wantErr: true,
		},
		{
			name:     "nonexistent file",
			content:  "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var path string
			if tt.wantErr && tt.content == "" {
				path = filepath.Join(tmpDir, "nonexistent.md")
			} else {
				path = filepath.Join(tmpDir, "test.md")
				if err := os.WriteFile(path, []byte(tt.content), 0644); err != nil {
					t.Fatal(err)
				}
			}

			body, err := ExtractBodyOnly(path)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if body != tt.wantBody {
				t.Errorf("body = %q, want %q", body, tt.wantBody)
			}
		})
	}
}

func TestFindSkillFiles(t *testing.T) {
	tmpDir := t.TempDir()

	skillFile := filepath.Join(tmpDir, "skill.md")
	referenceFile := filepath.Join(tmpDir, "README.md")
	nestedSkillDir := filepath.Join(tmpDir, "nested")
	nestedSkillFile := filepath.Join(nestedSkillDir, "SKILL.MD")

	skillContent := `---
name: test-skill
---
Body`

	referenceContent := `# Reference Documentation

This is a reference file.`

	if err := os.WriteFile(skillFile, []byte(skillContent), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(referenceFile, []byte(referenceContent), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(nestedSkillDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nestedSkillFile, []byte(skillContent), 0644); err != nil {
		t.Fatal(err)
	}

	t.Run("find skill files in directory", func(t *testing.T) {
		files, err := FindSkillFiles(tmpDir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(files) < 2 {
			t.Errorf("expected at least 2 files, got %d", len(files))
		}

		foundSkill := false
		foundRef := false
		for _, f := range files {
			if f.Path == skillFile && f.FileType == FileTypeSkill {
				foundSkill = true
			}
			if f.Path == referenceFile && f.FileType == FileTypeReference {
				foundRef = true
			}
		}

		if !foundSkill {
			t.Error("did not find skill.md as FileTypeSkill")
		}
		if !foundRef {
			t.Error("did not find README.md as FileTypeReference")
		}
	})

	t.Run("find single skill file", func(t *testing.T) {
		files, err := FindSkillFiles(skillFile)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(files) != 1 {
			t.Fatalf("expected 1 file, got %d", len(files))
		}

		if files[0].FileType != FileTypeSkill {
			t.Errorf("expected FileTypeSkill, got %d", files[0].FileType)
		}
	})

	t.Run("nonexistent path", func(t *testing.T) {
		_, err := FindSkillFiles(filepath.Join(tmpDir, "nonexistent"))
		if err == nil {
			t.Error("expected error for nonexistent path")
		}
	})

	t.Run("nested directory with uppercase SKILL.MD", func(t *testing.T) {
		files, err := FindSkillFiles(nestedSkillDir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(files) != 1 {
			t.Fatalf("expected 1 file, got %d", len(files))
		}

		if files[0].FileType != FileTypeSkill {
			t.Errorf("expected FileTypeSkill for SKILL.MD, got %d", files[0].FileType)
		}
	})
}

func TestFileTypeConstants(t *testing.T) {
	if FileTypeSkill != 0 {
		t.Errorf("FileTypeSkill = %d, want 0", FileTypeSkill)
	}
	if FileTypeReference != 1 {
		t.Errorf("FileTypeReference = %d, want 1", FileTypeReference)
	}
}
