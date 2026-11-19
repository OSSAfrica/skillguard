package model

import (
	"strings"
	"unicode/utf8"
)

// PositionAt converts a byte offset in the original UTF-8 input to a one-based
// line and Unicode code-point column. It never expands tabs or normalizes text.
func PositionAt(text string, offset int) SourcePosition {
	if offset < 0 || offset > len(text) {
		return SourcePosition{}
	}
	prefix := text[:offset]
	line := strings.Count(prefix, "\n") + 1
	start := strings.LastIndexByte(prefix, '\n') + 1
	return SourcePosition{Line: line, Column: utf8.RuneCountInString(prefix[start:]) + 1}
}
