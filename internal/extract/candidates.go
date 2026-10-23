package extract

import (
	"regexp"
	"strings"
)

type candidate struct {
	text    string
	line    int
	context string
}

var (
	commandStart      = regexp.MustCompile(`^(?:[A-Za-z_][A-Za-z0-9_]*=\S+\s+)*(?:npm|npx|pip3?|python(?:3(?:\.[0-9]+)?)?|uvx|pipx|curl|wget|sudo|env|command|bash|sh|zsh|yarn|pnpm|uv|gem|cargo|go|bun|\$[^\s]+)(?:\s|$)`)
	inlineCode        = regexp.MustCompile("`+([^`\n]+)`+")
	instructionPrefix = regexp.MustCompile(`(?i)^(?:please\s+)?(?:run|execute|install with|install using|use|install:)\s+`)
	listPrefix        = regexp.MustCompile(`^(?:[-*+] |[0-9]+[.)] )`)
)

// candidates deliberately recognizes a documented subset of Markdown and shell
// suggestions. It does not turn arbitrary prose into shell commands.
func candidates(content string) []candidate {
	lines := strings.Split(content, "\n")
	var found []candidate
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if marker := fenceMarker(line); marker != "" {
			lang := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(line, marker)))
			start := i + 1
			var block []string
			for i++; i < len(lines); i++ {
				if strings.HasPrefix(strings.TrimSpace(lines[i]), marker) {
					break
				}
				block = append(block, stripPrompt(strings.TrimSuffix(lines[i], "\r")))
			}
			shell := lang == "" || lang == "sh" || lang == "bash" || lang == "shell" || lang == "zsh" || lang == "console" || lang == "terminal"
			if shell {
				found = append(found, candidate{strings.Join(block, "\n"), start + 1, "fenced"})
			} else {
				// Recognizable commands in other languages are evidence of a
				// coverage gap, not an invitation to parse those languages as Bash.
				for j, text := range block {
					if commandStart.MatchString(strings.TrimSpace(text)) {
						found = append(found, candidate{text, start + j + 1, "unsupported_fence"})
					}
				}
			}
			continue
		}

		matches := inlineCode.FindAllStringSubmatch(line, -1)
		for _, match := range matches {
			text := stripPrompt(strings.TrimSpace(match[1]))
			if commandStart.MatchString(text) {
				context := "inline"
				lower := strings.ToLower(line)
				if strings.HasPrefix(lower, "the command ") || strings.HasPrefix(lower, "for example") || strings.HasPrefix(lower, "avoid ") || strings.HasPrefix(lower, "do not ") {
					context = "example"
				}
				found = append(found, candidate{text, i + 1, context})
			}
		}
		if len(matches) > 0 {
			continue
		}
		line = listPrefix.ReplaceAllString(line, "")
		context := "plain"
		if loc := instructionPrefix.FindStringIndex(line); loc != nil {
			line = line[loc[1]:]
			context = "instruction"
		}
		line = stripPrompt(line)
		if !commandStart.MatchString(line) {
			continue
		}
		start := i + 1
		for continues(line) && i+1 < len(lines) {
			i++
			line += "\n" + stripPrompt(strings.TrimSpace(lines[i]))
		}
		found = append(found, candidate{line, start, context})
	}
	return found
}

func fenceMarker(line string) string {
	for _, marker := range []string{"```", "~~~"} {
		if strings.HasPrefix(line, marker) {
			n := len(marker)
			for n < len(line) && line[n] == marker[0] {
				n++
			}
			return line[:n]
		}
	}
	return ""
}

func stripPrompt(line string) string {
	trimmed := strings.TrimLeft(line, " \t")
	if strings.HasPrefix(trimmed, "$ ") || strings.HasPrefix(trimmed, "> ") {
		return trimmed[2:]
	}
	return line
}

func continues(line string) bool {
	line = strings.TrimSpace(line)
	return strings.HasSuffix(line, "\\") || strings.HasSuffix(line, "&&") || strings.HasSuffix(line, "||") || strings.HasSuffix(line, "|")
}
