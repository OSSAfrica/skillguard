package parser

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"skillguard/internal/model"

	"gopkg.in/yaml.v3"
)

var (
	ErrNoFrontmatter = errors.New("no YAML frontmatter found")
	ErrInvalidYAML   = errors.New("invalid YAML in frontmatter")
)

type Frontmatter struct {
	Name         string      `yaml:"name"`
	Description  string      `yaml:"description"`
	AllowedTools interface{} `yaml:"allowed-tools"` // string or []string
	Source       string      `yaml:"source"`
	Triggers     []string    `yaml:"triggers"`
	Location     string      `yaml:"location"`
}

func parseAllowedTools(v interface{}) []string {
	if v == nil {
		return nil
	}
	switch t := v.(type) {
	case string:
		if t == "" {
			return nil
		}
		var tools []string
		for _, tool := range strings.Split(t, ",") {
			tool = strings.TrimSpace(tool)
			if tool != "" {
				tools = append(tools, tool)
			}
		}
		return tools
	case []interface{}:
		var tools []string
		for _, item := range t {
			if s, ok := item.(string); ok {
				tools = append(tools, s)
			}
		}
		return tools
	}
	return nil
}

func ParseSkillFile(path string) (*model.SkillMetadata, string, error) {
	content, err := os.ReadFile(path) // #nosec G304 -- CLI tool reads user-specified paths by design
	if err != nil {
		return nil, "", fmt.Errorf("failed to read file: %w", err)
	}

	frontmatter, body, err := extractFrontmatter(string(content))
	if err != nil {
		return nil, "", err
	}

	metadata := &model.SkillMetadata{
		Name:         frontmatter.Name,
		Description:  frontmatter.Description,
		AllowedTools: parseAllowedTools(frontmatter.AllowedTools),
		Source:       frontmatter.Source,
		Triggers:     frontmatter.Triggers,
		Location:     path,
	}

	if metadata.Name == "" {
		metadata.Name = strings.TrimSuffix(filepath.Base(path), ".md")
	}

	return metadata, body, nil
}

func extractFrontmatter(content string) (*Frontmatter, string, error) {
	content = strings.TrimSpace(content)

	if !strings.HasPrefix(content, "---") {
		return nil, "", ErrNoFrontmatter
	}

	lines := strings.Split(content, "\n")
	endIndex := -1

	for i := 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "---" {
			endIndex = i
			break
		}
	}

	if endIndex == -1 {
		return nil, "", ErrNoFrontmatter
	}

	yamlContent := strings.Join(lines[1:endIndex], "\n")

	var fm Frontmatter
	if err := yaml.Unmarshal([]byte(yamlContent), &fm); err != nil {
		return nil, "", fmt.Errorf("%w: %v", ErrInvalidYAML, err)
	}

	body := strings.TrimSpace(strings.Join(lines[endIndex+1:], "\n"))

	return &fm, body, nil
}

func ExtractBodyOnly(path string) (string, error) {
	content, err := os.ReadFile(path) // #nosec G304 -- CLI tool reads user-specified paths by design
	if err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}

	frontmatter, body, err := extractFrontmatter(string(content))
	if err != nil {
		if err == ErrNoFrontmatter {
			return string(content), nil
		}
		return string(content), nil
	}

	if frontmatter != nil && body == "" {
		return "", fmt.Errorf("empty body in %s", path)
	}

	return body, nil
}

type FileType int

const (
	FileTypeSkill FileType = iota
	FileTypeReference
)

type FoundFile struct {
	Path     string
	FileType FileType
}

// FindSkillFiles locates the Markdown files to scan under path.
//
// It returns the files found, warnings for anything that had to be skipped, and
// an error only when the requested path itself cannot be scanned. A single
// unreadable directory must not discard the results of an otherwise good scan.
func FindSkillFiles(path string) ([]FoundFile, []string, error) {
	path = strings.TrimSpace(path)

	info, err := os.Stat(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to access path: %w", err)
	}

	if !info.IsDir() {
		file, ok := classifyFile(path, true)
		if !ok {
			return nil, nil, nil
		}

		return []FoundFile{file}, nil, nil
	}

	var (
		files    []FoundFile
		warnings []string
	)

	walkSkillDir(path, map[string]bool{}, &files, &warnings)

	return files, warnings, nil
}

// walkSkillDir descends into dir, following symlinked directories. Skill trees
// are routinely built from symlinks (~/.claude/skills/<name> pointing elsewhere)
// and filepath.Walk does not follow them, so those skills were skipped without
// a word. Directories already visited are skipped, which also breaks cycles.
func walkSkillDir(dir string, visited map[string]bool, files *[]FoundFile, warnings *[]string) {
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		*warnings = append(*warnings, fmt.Sprintf("skipped %s: %v", dir, err))
		return
	}

	if visited[resolved] {
		return
	}
	visited[resolved] = true

	entries, err := os.ReadDir(dir)
	if err != nil {
		*warnings = append(*warnings, fmt.Sprintf("skipped %s: %v", dir, err))
		return
	}

	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())

		// Stat, not the DirEntry type, so a symlink is classified by its target.
		info, err := os.Stat(path)
		if err != nil {
			*warnings = append(*warnings, fmt.Sprintf("skipped %s: %v", path, err))
			continue
		}

		if info.IsDir() {
			walkSkillDir(path, visited, files, warnings)
			continue
		}

		if !strings.HasSuffix(strings.ToLower(entry.Name()), ".md") {
			continue
		}

		file, ok := classifyFile(path, false)
		if !ok {
			*warnings = append(*warnings, fmt.Sprintf("skipped %s: unreadable", path))
			continue
		}

		*files = append(*files, file)
	}
}

// classifyFile decides whether a Markdown file is a skill definition or a
// reference document. A file the user named explicitly is always scanned, with
// or without frontmatter: skipping it silently reported a pass for a file that
// was never read.
func classifyFile(path string, explicit bool) (FoundFile, bool) {
	if !strings.HasSuffix(strings.ToLower(filepath.Base(path)), ".md") {
		return FoundFile{}, false
	}

	content, err := os.ReadFile(path) // #nosec G304 -- CLI tool reads user-specified paths by design
	if err != nil {
		return FoundFile{}, false
	}

	name := strings.ToLower(filepath.Base(path))
	isSkillName := name == "skill.md" || name == "skills.md"
	hasFrontmatter := strings.HasPrefix(strings.TrimSpace(string(content)), "---")

	if hasFrontmatter && (explicit || isSkillName) {
		return FoundFile{Path: path, FileType: FileTypeSkill}, true
	}

	return FoundFile{Path: path, FileType: FileTypeReference}, true
}
