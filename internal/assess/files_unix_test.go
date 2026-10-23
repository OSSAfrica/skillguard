//go:build !windows

package assess

import (
	"context"
	"path/filepath"
	"syscall"
	"testing"
)

func TestFIFOInputDoesNotBlock(t *testing.T) {
	r, p, o := testSetup(t)
	if err := syscall.Mkfifo(filepath.Join(r.CWD, "requirements.txt"), 0600); err != nil {
		t.Fatal(err)
	}
	r.Inputs = []Input{{Path: "requirements.txt", Kind: "requirements"}}
	got := Evaluate(context.Background(), r, p, o)
	if got.ExitCode() != 2 || !hasRule(got, "SG_INPUT_UNAVAILABLE") {
		t.Fatal(got)
	}
}
