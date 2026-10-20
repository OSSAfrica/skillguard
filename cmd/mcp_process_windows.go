package cmd

import "os/exec"

// Execution is rejected during configuration on Windows; read-only tools work.
func configureGuardProcess(_ *exec.Cmd) {}
