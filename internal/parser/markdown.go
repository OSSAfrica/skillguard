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
	content, err := os.ReadFile(path)
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

func FindSkillFiles(path string) ([]string, error) {
	path = strings.TrimSpace(path)

	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to access path: %w", err)
	}

	var files []string

	if info.IsDir() {
		err = filepath.Walk(path, func(p string, fi os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if fi.IsDir() {
				if fi.Name() == "references" || fi.Name() == "templates" {
					return filepath.SkipDir
				}
				return nil
			}
			lowerName := strings.ToLower(fi.Name())
			if strings.HasSuffix(lowerName, ".md") {
				if lowerName == "skill.md" || lowerName == "skills.md" {
					files = append(files, p)
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	} else {
		if strings.HasSuffix(strings.ToLower(info.Name()), ".md") {
			files = []string{path}
		}
	}

	return files, nil
}
