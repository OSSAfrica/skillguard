package update

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const cask = "ossafrica/skillguard/skillguard"

type Installation struct {
	Method    string
	Path      string
	Guidance  string
	Brew      string
	Available string
}

// Runner keeps subprocesses explicit and allows tests without installed managers.
type Runner func(context.Context, string, ...string) ([]byte, error)

func Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if !filepath.IsAbs(name) {
		return nil, fmt.Errorf("updater subprocess requires an absolute executable path")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	// Callers select package managers via LookPath or pass a checksum-verified
	// release executable. Arguments are fixed by the updater; no shell is used.
	command := exec.CommandContext(ctx, name, args...) // #nosec G204 -- intentional execution of an explicit manager or verified release binary, with fixed argv.
	// Detection and check-only must not refresh taps or change Homebrew state.
	command.Env = append(os.Environ(), "HOMEBREW_NO_AUTO_UPDATE=1", "HOMEBREW_NO_ANALYTICS=1")
	return command.Output()
}

func inside(path, directory string) bool {
	rel, err := filepath.Rel(directory, path)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// Detect establishes ownership of this executable, rather than any other copy on PATH.
func Detect(ctx context.Context, executable, distribution, version string, run Runner) (Installation, error) {
	path, err := filepath.EvalSymlinks(executable)
	if err != nil {
		return Installation{}, err
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return Installation{}, err
	}
	i := Installation{Method: "unknown", Path: path, Guidance: "Installation ownership is unclear; update through the original installer."}
	dir := filepath.Dir(path)
	// Both default and operator-selected plugin caches retain their pinned archive.
	asset := "skillguard_" + strings.TrimPrefix(version, "v") + "_"
	entries, err := os.ReadDir(dir)
	if err != nil {
		return i, err
	}
	for _, entry := range entries {
		if filepath.Base(filepath.Dir(dir)) == "v"+strings.TrimPrefix(version, "v") && strings.HasPrefix(entry.Name(), asset) && strings.HasSuffix(entry.Name(), ".tar.gz") {
			i.Method, i.Guidance = "plugin/pinned archive", "Update the owning plugin, run its setup workflow, then restart the agent. Pinned runtime binaries cannot be updated independently."
			return i, nil
		}
	}
	if strings.Contains(filepath.ToSlash(path), "/plugin-runtime/") {
		i.Method, i.Guidance = "plugin", "Update the owning plugin, run setup, then restart the agent."
		return i, nil
	}
	if _, err := os.Lstat(filepath.Join(dir, "installation.json")); err == nil {
		i.Method, i.Guidance = "protected launcher", "Install a reviewed scanner and launcher bundle into a new prefix; validate the profile before switching installations."
		return i, nil
	}
	if distribution == "docker" {
		i.Method, i.Guidance = "docker", "On the host, pull the desired image (for example: docker pull ghcr.io/ossafrica/skillguard:latest) and recreate the container. Preserve explicit version/digest pins."
		return i, nil
	}
	if brew, err := exec.LookPath("brew"); err == nil {
		if detected, ok := detectBrew(ctx, path, brew, run); ok {
			return detected, nil
		}
	}
	// A release build is not sufficient evidence to overwrite a manager's files.
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		if part == "Cellar" || part == "Caskroom" || part == "node_modules" || part == ".nix" || part == "nix" || part == "snap" {
			return i, nil
		}
	}
	for _, manager := range []struct {
		name string
		args []string
	}{
		{"dpkg-query", []string{"-S", path}}, {"rpm", []string{"-qf", path}}, {"pacman", []string{"-Qo", path}}, {"apk", []string{"info", "--who-owns", path}},
	} {
		if command, err := exec.LookPath(manager.name); err == nil {
			if _, err := run(ctx, command, manager.args...); err == nil {
				i.Method, i.Guidance = manager.name, "Update SkillGuard through the operating system package manager."
				return i, nil
			}
		}
	}
	switch distribution {
	case "source":
		i.Method, i.Guidance = "source", "Update your reviewed source checkout and rebuild using the original build/install command."
	case "release":
		i.Method, i.Guidance = "standalone", "Update this release binary in place after verifying the published archive checksum."
	}
	return i, nil
}

func detectBrew(ctx context.Context, path, brew string, run Runner) (Installation, bool) {
	root, err := run(ctx, brew, "--caskroom", cask)
	if err != nil {
		return Installation{}, false
	}
	directory, err := filepath.EvalSymlinks(strings.TrimSpace(string(root)))
	if err != nil || !filepath.IsAbs(directory) || !inside(path, directory) {
		return Installation{}, false
	}
	data, err := run(ctx, brew, "info", "--json=v2", "--cask", cask)
	if err != nil {
		return Installation{}, false
	}
	var info struct {
		Casks []struct {
			Token     string `json:"token"`
			Tap       string `json:"tap"`
			Installed string `json:"installed"`
			Version   string `json:"version"`
		} `json:"casks"`
	}
	if json.Unmarshal(data, &info) != nil || len(info.Casks) != 1 {
		return Installation{}, false
	}
	item := info.Casks[0]
	if item.Token != "skillguard" || item.Tap != "ossafrica/skillguard" || item.Installed == "" || !inside(path, filepath.Join(directory, item.Installed)) {
		return Installation{}, false
	}
	return Installation{Method: "homebrew", Path: path, Brew: brew, Available: item.Version, Guidance: fmt.Sprintf("Upgrade through brew upgrade --cask %s", cask)}, true
}
