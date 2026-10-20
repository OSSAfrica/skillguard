package extract

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	"skillguard/internal/model"
)

// input verifies bounded readability within the document directory. It does not
// resolve/install manifest dependencies, recurse through requirements includes,
// or read config/lockfile contents into the report.
func (e *extractor) input(command *model.DocumentCommand, ref, kind string) {
	input := model.DependencyInput{Path: bounded(ref, 512), Kind: kind, Status: "referenced"}
	defer func() { command.Inputs = append(command.Inputs, input) }()
	e.localInputs++
	if e.localInputs > 16 {
		e.gap("input_limit", "Further dependency-file reads stopped at the 16-input limit.", command.Location)
		return
	}
	if len(ref) > 512 || ref == "" || filepath.IsAbs(ref) || strings.Contains(ref, ":") || strings.Contains(ref, "\\") {
		input.Path, input.Status = "[outside document boundary]", "outside_boundary"
		e.gap("input_outside_boundary", "Dependency input is not a supported local relative path.", command.Location)
		return
	}
	if e.base == "" {
		e.gap("input_base_unavailable", "Stdin has no local dependency-file boundary; the source label grants no file access.", command.Location)
		return
	}
	root, err := os.OpenRoot(e.base)
	if err != nil {
		input.Status = "unavailable"
		e.gap("input_unavailable", "The document's local input boundary could not be opened.", command.Location)
		return
	}
	defer func() { _ = root.Close() }()
	info, err := root.Stat(ref)
	if err != nil || !info.Mode().IsRegular() {
		input.Status = "unavailable"
		e.gap("input_unavailable", "A dependency input is missing, unreadable, non-regular, or outside the document boundary.", command.Location)
		return
	}
	if info.Size() > MaxInputBytes {
		input.Status = "unavailable"
		e.gap("input_limit", "A dependency input exceeds the 1 MiB read limit.", command.Location)
		return
	}
	file, err := root.Open(ref)
	if err != nil {
		input.Status = "unavailable"
		e.gap("input_unavailable", "A dependency input could not be read within the document boundary.", command.Location)
		return
	}
	defer func() { _ = file.Close() }()
	// Discard, rather than retain, contents: requirements/configuration can
	// contain secrets. The next phase will resolve supported dependency files.
	n, err := io.Copy(io.Discard, io.LimitReader(file, MaxInputBytes+1))
	if err != nil || n > MaxInputBytes {
		input.Status = "unavailable"
		e.gap("input_unavailable", "A dependency input could not be read completely within the limit.", command.Location)
		return
	}
	input.Status = "readable"
	e.gap("dependency_input_unresolved", "Dependency input was readable but its contents and nested dependencies have not been resolved.", command.Location)
}
