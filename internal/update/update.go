package update

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type Options struct {
	Executable   string
	Version      string
	Distribution string
	Check        bool
	Out          io.Writer
	Releases     *Releases
	Run          Runner
	Upgrade      func(context.Context, string, io.Writer, ...string) error
}

func Execute(ctx context.Context, options Options) error {
	if options.Releases == nil {
		options.Releases = NewReleases()
	}
	if options.Run == nil {
		options.Run = Run
	}
	if options.Upgrade == nil {
		options.Upgrade = runBrew
	}
	i, err := Detect(ctx, options.Executable, options.Distribution, options.Version, options.Run)
	if err != nil {
		return err
	}
	fmt.Fprintf(options.Out, "Current version: %s\nExecutable: %s\nInstallation: %s\n", options.Version, i.Path, i.Method)
	latest, err := options.Releases.Latest(ctx)
	if err != nil {
		return fmt.Errorf("check latest release: %w", err)
	}
	fmt.Fprintf(options.Out, "Latest stable release: %s\n", latest)
	comparison, versionErr := Compare(options.Version, latest)
	if i.Method == "homebrew" {
		fmt.Fprintf(options.Out, "Homebrew available version (local metadata): %s\n", i.Available)
	}
	if versionErr != nil {
		fmt.Fprintln(options.Out, "Current build cannot be compared with a stable release.", i.Guidance)
		if options.Check {
			return nil
		}
		return fmt.Errorf("automatic update is unavailable for this build")
	}
	if comparison >= 0 {
		fmt.Fprintln(options.Out, "Already at or ahead of the latest stable release.")
		return nil
	}
	fmt.Fprintln(options.Out, "Update available.")
	if options.Check {
		fmt.Fprintln(options.Out, i.Guidance)
		return nil
	}
	switch i.Method {
	case "homebrew":
		return upgradeBrew(ctx, i, options.Version, options.Out, options.Run, options.Upgrade)
	case "standalone":
		return upgradeBinary(ctx, i, latest, options)
	default:
		return fmt.Errorf("automatic update unavailable for %s: %s", i.Method, i.Guidance)
	}
}

func upgradeBinary(ctx context.Context, i Installation, latest string, options Options) error {
	// Verify this copy is an unmodified published binary before adopting it.
	original, err := os.ReadFile(i.Path)
	if err != nil {
		return err
	}
	published, err := options.Releases.Binary(ctx, options.Version, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return fmt.Errorf("verify current release installation: %w", err)
	}
	if !bytes.Equal(original, published) {
		return fmt.Errorf("running binary differs from the published release; use the original installer")
	}
	binary, err := options.Releases.Binary(ctx, latest, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return err
	}
	fmt.Fprintf(options.Out, "Installing verified release %s to %s\n", latest, i.Path)
	if err := Replace(ctx, i.Path, original, binary, latest, options.Run); err != nil {
		return err
	}
	fmt.Fprintf(options.Out, "Updated to %s. Restart any running SkillGuard servers or agents that use this copy.\n", latest)
	return nil
}

func runBrew(ctx context.Context, brew string, out io.Writer, args ...string) error {
	// The executable comes from ownership detection and callers supply fixed argv.
	command := exec.CommandContext(ctx, brew, args...) // #nosec G204 -- explicit package manager, no shell or user-supplied arguments.
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, out, out
	command.Env = append(os.Environ(), "HOMEBREW_NO_AUTO_UPDATE=1", "HOMEBREW_NO_ANALYTICS=1")
	return command.Run()
}

func upgradeBrew(ctx context.Context, i Installation, current string, out io.Writer, run Runner, upgrade func(context.Context, string, io.Writer, ...string) error) error {
	fmt.Fprintln(out, "Refreshing Homebrew metadata and upgrading the SkillGuard cask.")
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	for _, args := range [][]string{{"update"}, {"upgrade", "--cask", cask}} {
		if err := upgrade(ctx, i.Brew, out, args...); err != nil {
			return fmt.Errorf("homebrew %s failed: %w", args[0], err)
		}
	}
	prefix, err := run(ctx, i.Brew, "--prefix")
	if err != nil {
		return err
	}
	path := filepath.Join(strings.TrimSpace(string(prefix)), "bin", "skillguard")
	updated, err := Detect(ctx, path, "release", current, run)
	if err != nil {
		return err
	}
	if updated.Method != "homebrew" {
		return fmt.Errorf("cannot verify Homebrew ownership after upgrade")
	}
	version, err := run(ctx, updated.Path, "--version")
	if err != nil {
		return err
	}
	newVersion := strings.TrimPrefix(strings.TrimSpace(string(version)), "skillguard version ")
	comparison, err := Compare(current, newVersion)
	if err != nil {
		return err
	}
	if comparison >= 0 {
		return fmt.Errorf("homebrew has not installed a newer version; its tap may be behind the upstream release")
	}
	fmt.Fprintf(out, "Updated through Homebrew to %s. Restart running SkillGuard servers or agents.\n", newVersion)
	return nil
}
