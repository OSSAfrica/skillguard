package update

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func verifyVersion(ctx context.Context, path, version string, run Runner) error {
	out, err := run(ctx, path, "--version")
	if err != nil {
		return fmt.Errorf("verify executable: %w", err)
	}
	if strings.TrimSpace(string(out)) != "skillguard version "+strings.TrimPrefix(version, "v") {
		return fmt.Errorf("executable did not report expected version %s", version)
	}
	return nil
}

// Replace checks the staged executable before changing the installation and keeps
// a backup until the installed executable has passed the same version check.
func Replace(ctx context.Context, path string, original, binary []byte, version string, run Runner) error {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer root.Close()
	name := filepath.Base(path)
	lock := path + ".update-lock"
	if err := os.Mkdir(lock, 0o700); err != nil {
		return fmt.Errorf("cannot lock update (another update or insufficient permissions): %w", err)
	}
	defer os.Remove(lock)
	info, err := root.Lstat(name)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
		return fmt.Errorf("refusing to replace nonregular or privileged executable")
	}
	current, err := root.ReadFile(name)
	if err != nil {
		return err
	}
	if !bytes.Equal(current, original) {
		return fmt.Errorf("installation changed during update; retry")
	}
	stage, err := os.CreateTemp(filepath.Dir(path), ".skillguard-update-*.exe")
	if err != nil {
		return err
	}
	staged := stage.Name()
	defer os.Remove(staged)
	if _, err := stage.Write(binary); err != nil {
		_ = stage.Close()
		return err
	}
	if err := stage.Chmod(info.Mode().Perm()); err != nil {
		_ = stage.Close()
		return err
	}
	if err := stage.Sync(); err != nil {
		_ = stage.Close()
		return err
	}
	if err := stage.Close(); err != nil {
		return err
	}
	if err := verifyVersion(ctx, staged, version, run); err != nil {
		return err
	}
	// The stage may run for several seconds; recheck the target just before commit.
	current, err = root.ReadFile(name)
	if err != nil {
		return err
	}
	if sha256.Sum256(current) != sha256.Sum256(original) {
		return fmt.Errorf("installation changed during update; retry")
	}
	backup := filepath.Join(lock, "previous")
	if runtime.GOOS == "windows" {
		reservation, err := os.CreateTemp(filepath.Dir(path), ".skillguard-previous-*.exe")
		if err != nil {
			return err
		}
		backup = reservation.Name()
		if err := reservation.Close(); err != nil {
			return err
		}
		if err := os.Remove(backup); err != nil {
			return err
		}
		// Windows cannot overwrite a running executable. Move it aside first.
		if err := os.Rename(path, backup); err != nil {
			return fmt.Errorf("move running executable aside: %w", err)
		}
	} else {
		if err := os.Link(path, backup); err != nil {
			return fmt.Errorf("preserve previous executable: %w", err)
		}
	}
	if err := os.Rename(staged, path); err != nil {
		if runtime.GOOS == "windows" {
			if restore := os.Rename(backup, path); restore != nil {
				return fmt.Errorf("install failed: %v; restore failed: %v; previous binary remains at %s", err, restore, backup)
			}
		} else {
			_ = os.Remove(backup)
		}
		return err
	}
	if err := verifyVersion(ctx, path, version, run); err != nil {
		if runtime.GOOS == "windows" {
			_ = os.Remove(path)
		}
		if restore := os.Rename(backup, path); restore != nil {
			return fmt.Errorf("verification failed: %v; restore failed: %v; previous binary remains at %s", err, restore, backup)
		}
		return fmt.Errorf("%w; previous executable restored", err)
	}
	// On Windows the old process may keep the backup locked until it exits.
	if err := os.Remove(backup); err != nil && runtime.GOOS != "windows" {
		return fmt.Errorf("updated successfully, but previous executable remains at %s: %w", backup, err)
	}
	return nil
}
