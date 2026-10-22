package extract

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
	"skillguard/internal/model"
)

// Action inventories the entire proposed action, bypassing documentation
// discovery. Only a single foreground simple Bash command is fully supported.
// argv is quoted as literal shell words; it is never evaluated or executed.
func Action(argv []string, shell string) *model.Extraction {
	text := shell
	if argv != nil {
		words := make([]string, len(argv))
		for i, arg := range argv {
			words[i] = "'" + strings.ReplaceAll(arg, "'", "'\\''") + "'"
		}
		text = strings.Join(words, " ")
	}
	e := &extractor{result: model.Extraction{Status: "complete", Commands: []model.DocumentCommand{}, Gaps: []model.CoverageGap{}}, source: "action"}
	if len(text) > MaxInputBytes {
		e.gap("input_limit", "Action exceeds its static parsing limit.", e.span(1, 1))
		return &e.result
	}
	f, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(text), "")
	if err != nil {
		e.gap("invalid_shell", "Action is not supported Bash syntax.", e.span(1, 1))
		return &e.result
	}
	simple := len(f.Stmts) == 1
	if simple {
		s := f.Stmts[0]
		_, call := s.Cmd.(*syntax.CallExpr)
		simple = call && !s.Background && !s.Coprocess && !s.Negated && len(s.Redirs) == 0
	}
	if !simple {
		e.gap("action_structure", "Only one foreground simple command can be assessed completely.", e.span(1, 1))
	}
	e.parse(candidate{text: text, line: 1, context: "action"})
	if len(e.result.Commands) == 0 {
		e.gap("no_assessable_commands", "No supported action was identified.", e.span(1, 1))
	}
	return &e.result
}
