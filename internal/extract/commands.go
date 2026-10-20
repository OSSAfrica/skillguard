// Package extract statically inventories a supported subset of documentation
// commands. It never invokes a shell, package manager, or network client.
package extract

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"skillguard/internal/model"

	"mvdan.cc/sh/v3/syntax"
)

const (
	MaxInputBytes = 1 << 20
	maxCommands   = 256
	maxGaps       = 256
)

type extractor struct {
	result      model.Extraction
	source      string
	base        string
	limited     bool
	localInputs int
}

// Extract inventories commands and local dependency-file references. base is
// the explicitly scanned document's directory, or empty for stdin. Source is an
// opaque display label and is never used as a filesystem/network destination.
func Extract(source, content, base string) *model.Extraction {
	e := &extractor{
		result: model.Extraction{Status: "complete", Commands: []model.DocumentCommand{}, Gaps: []model.CoverageGap{}},
		source: SafeSource(source), base: base,
	}
	if len(content) > MaxInputBytes {
		content = content[:MaxInputBytes]
		e.gap("input_limit", "Command extraction stopped at the 1 MiB input limit.", e.span(1, 1))
	}
	for _, c := range candidates(content) {
		if e.limited {
			break
		}
		if c.context == "unsupported_fence" {
			e.gap("unsupported_language", "A command-like line occurs in a non-shell code block.", e.span(c.line, c.line))
			continue
		}
		e.parse(c)
	}
	if len(e.result.Commands) == 0 {
		e.gap("no_assessable_commands", "No supported commands were extracted; this is not an execution approval.", e.span(1, 1))
	}
	return &e.result
}

func (e *extractor) span(start, end int) model.SourceSpan {
	return model.SourceSpan{Source: e.source, StartLine: start, EndLine: end}
}

func (e *extractor) gap(code, message string, location model.SourceSpan) {
	e.result.Status = "partial"
	if len(e.result.Gaps) >= maxGaps {
		e.limited = true
		e.result.Gaps[maxGaps-1] = model.CoverageGap{Code: "extraction_limit", Message: "Further extraction was stopped at the coverage-gap limit.", Location: location}
		return
	}
	e.result.Gaps = append(e.result.Gaps, model.CoverageGap{Code: code, Message: message, Location: location})
}

func (e *extractor) parse(c candidate) {
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(c.text), "")
	if err != nil {
		// Parser errors can quote secrets from the input. Emit only a fixed code
		// and span; never echo the parser's untrusted error message.
		e.gap("invalid_shell", "Command candidate could not be parsed as supported shell syntax.", e.span(c.line, c.line+strings.Count(c.text, "\n")))
		return
	}
	piped := map[*syntax.CallExpr]bool{}
	syntax.Walk(file, func(node syntax.Node) bool {
		binary, ok := node.(*syntax.BinaryCmd)
		if !ok || (binary.Op != syntax.Pipe && binary.Op != syntax.PipeAll) {
			return true
		}
		sink, ok := binary.Y.Cmd.(*syntax.CallExpr)
		if !ok || len(sink.Args) == 0 {
			return true
		}
		name, literal := literalWord(sink.Args[0].Parts, false)
		if literal && (name == "sh" || name == "bash" || name == "zsh" || name == "python" || name == "python3") {
			// Only direct pipelines are annotated. Rewalking every pipeline's
			// entire left subtree would make long hostile pipelines quadratic.
			if call, ok := binary.X.Cmd.(*syntax.CallExpr); ok {
				piped[call] = true
			}
		}
		return true
	})
	syntax.Walk(file, func(node syntax.Node) bool {
		if e.limited {
			return false
		}
		switch n := node.(type) {
		case *syntax.CallExpr:
			e.call(n, c, piped[n])
		case *syntax.IfClause, *syntax.ForClause, *syntax.WhileClause, *syntax.FuncDecl, *syntax.CaseClause, *syntax.Subshell:
			e.gap("control_flow", "Commands are inventoried without resolving shell control flow or working-directory changes.", e.span(c.line+int(node.Pos().Line())-1, c.line+int(node.End().Line())-1))
		case *syntax.DeclClause:
			e.gap("environment_unresolved", "Shell declarations and exports are not evaluated.", e.span(c.line+int(node.Pos().Line())-1, c.line+int(node.End().Line())-1))
		case *syntax.Redirect:
			e.gap("redirection_unresolved", "Shell redirection and here-document contents are not resolved.", e.span(c.line+int(node.Pos().Line())-1, c.line+int(node.End().Line())-1))
		}
		return true
	})
}

func (e *extractor) call(call *syntax.CallExpr, c candidate, piped bool) {
	location := e.span(c.line+int(call.Pos().Line())-1, c.line+int(call.End().Line())-1)
	if len(call.Args) == 0 {
		if len(call.Assigns) > 0 {
			e.gap("environment_unresolved", "Shell assignments are not evaluated.", location)
		}
		return
	}
	if len(e.result.Commands) >= maxCommands {
		e.gap("extraction_limit", "Further command extraction stopped at the 256-command limit.", location)
		e.limited = true
		return
	}
	if len(call.Args) > 512 {
		e.gap("argument_limit", "A command exceeds the 512-argument extraction limit.", location)
		return
	}
	args := make([]string, len(call.Args))
	for i, word := range call.Args {
		value, ok := literalWord(word.Parts, false)
		if !ok {
			e.gap("dynamic_shell", "Shell expansion, globbing, or substitution cannot be resolved statically.", location)
			return
		}
		args[i] = value
	}
	if len(call.Assigns) > 0 {
		e.gap("environment_unresolved", "Command environment overrides require additional assessment.", location)
	}
	if args[0] == "sudo" || args[0] == "env" || args[0] == "command" {
		wrapper := args[0]
		args = args[1:]
		for len(args) > 0 && (args[0] == "--" || (wrapper == "sudo" && args[0] == "-n")) {
			args = args[1:]
		}
		e.gap("wrapper_unresolved", "A command wrapper may alter execution context; only simple literal wrapping is inventoried.", location)
		if len(args) == 0 || strings.HasPrefix(args[0], "-") || strings.Contains(args[0], "=") {
			return
		}
	}
	command := model.DocumentCommand{Tool: args[0], Context: c.context, Location: location}
	tool, operation, rest, ok := classifyCommand(args)
	if !ok {
		e.gap("unsupported_command", "A shell command is outside the supported installation/download subset.", location)
		return
	}
	command.Tool, command.Operation = tool, operation
	if operation == "download" {
		command.PipedToExecution = piped
		e.download(&command, rest)
	} else {
		e.packages(&command, rest)
	}
	// Evidence is a reconstruction, never raw argv: unknown flags, environment
	// values, passwords, and arbitrary positional payloads are not copied out.
	digest := sha256.Sum256([]byte(c.text))
	command.Evidence = fmt.Sprintf("%s %s (untrusted candidate sha256:%x)", tool, operation, digest)
	e.result.Commands = append(e.result.Commands, command)
}

func classifyCommand(args []string) (tool, operation string, rest []string, ok bool) {
	tool = args[0]
	rest = args[1:]
	if tool == "python" || tool == "python3" || strings.HasPrefix(tool, "python3.") {
		if len(rest) < 3 || rest[0] != "-m" || (rest[1] != "pip" && rest[1] != "pip3") {
			return tool, "", nil, false
		}
		tool, rest = rest[1], rest[2:]
	}
	switch tool {
	case "npm":
		// Global flags before the subcommand are not reordered or guessed.
		if len(rest) > 0 && (rest[0] == "install" || rest[0] == "i" || rest[0] == "add" || rest[0] == "ci" || rest[0] == "exec") {
			operation, rest = rest[0], rest[1:]
			if operation == "i" || operation == "add" {
				operation = "install"
			}
			return tool, operation, rest, true
		}
	case "pip", "pip3":
		if len(rest) > 0 && rest[0] == "install" {
			return tool, "install", rest[1:], true
		}
	case "npx", "uvx":
		return tool, "exec", rest, true
	case "pipx":
		if len(rest) > 0 && rest[0] == "run" {
			return tool, "exec", rest[1:], true
		}
	case "curl", "wget":
		return tool, "download", rest, true
	}
	return tool, "", nil, false
}

func literalWord(parts []syntax.WordPart, quoted bool) (string, bool) {
	var result strings.Builder
	for _, part := range parts {
		switch p := part.(type) {
		case *syntax.Lit:
			value, ok := unescape(p.Value, quoted)
			if !ok {
				return "", false
			}
			result.WriteString(value)
		case *syntax.SglQuoted:
			if p.Dollar {
				return "", false
			}
			result.WriteString(p.Value)
		case *syntax.DblQuoted:
			value, ok := literalWord(p.Parts, true)
			if !ok || p.Dollar {
				return "", false
			}
			result.WriteString(value)
		default:
			return "", false
		}
	}
	return result.String(), true
}

func unescape(value string, quoted bool) (string, bool) {
	var result strings.Builder
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if ch == '\\' && i+1 < len(value) {
			next := value[i+1]
			if !quoted || strings.ContainsRune("$`\"\\\n", rune(next)) {
				i++
				if next != '\n' {
					result.WriteByte(next)
				}
				continue
			}
		}
		if !quoted && strings.ContainsRune("*?[~", rune(ch)) {
			return "", false
		}
		result.WriteByte(ch)
	}
	return result.String(), true
}
