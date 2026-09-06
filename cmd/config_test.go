package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig_ReadsValuesFromConfigFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	write(t, filepath.Join(home, ".skillguard.yaml"), "default_path: /skills\nthreshold: 85\n")

	cfg := loadConfig()

	if cfg.Threshold != 85 {
		t.Errorf("Threshold = %d, want 85 from the config file", cfg.Threshold)
	}
	if cfg.DefaultPath != "/skills" {
		t.Errorf("DefaultPath = %q, want %q from the config file", cfg.DefaultPath, "/skills")
	}
}

func TestLoadConfig_UsesDefaultsWithoutConfigFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	cfg := loadConfig()

	if cfg.Threshold != defaultThreshold {
		t.Errorf("Threshold = %d, want the default %d", cfg.Threshold, defaultThreshold)
	}
	if want := filepath.Join(home, ".agents", "skills"); cfg.DefaultPath != want {
		t.Errorf("DefaultPath = %q, want %q", cfg.DefaultPath, want)
	}
}

// Reading configuration must not write to the user's home directory.
func TestLoadConfig_DoesNotCreateAConfigFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	loadConfig()

	entries, err := os.ReadDir(home)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("loadConfig() created %d entries in HOME, want none", len(entries))
	}
}

// Saving twice must update the file rather than refusing to overwrite it.
func TestConfigSave_OverwritesAnExistingFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	cfg := loadConfig()
	cfg.Threshold = 80
	if err := cfg.Save(); err != nil {
		t.Fatalf("first Save() error = %v", err)
	}

	cfg = loadConfig()
	cfg.Threshold = 90
	if err := cfg.Save(); err != nil {
		t.Fatalf("second Save() error = %v", err)
	}

	if got := loadConfig().Threshold; got != 90 {
		t.Errorf("Threshold after re-saving = %d, want 90", got)
	}
}

// The documented location is ~/.skillguard.yaml.
func TestConfigSave_WritesTheDocumentedDotfile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	cfg := loadConfig()
	cfg.Threshold = 75
	if err := cfg.Save(); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	if _, err := os.Stat(filepath.Join(home, ".skillguard.yaml")); err != nil {
		t.Errorf("expected ~/.skillguard.yaml to exist: %v", err)
	}
}

func TestValidateThreshold(t *testing.T) {
	tests := []struct {
		threshold int
		wantErr   bool
	}{
		{0, false},
		{70, false},
		{100, false},
		{-1, true},
		{101, true},
	}

	for _, tt := range tests {
		err := validateThreshold(tt.threshold)
		if (err != nil) != tt.wantErr {
			t.Errorf("validateThreshold(%d) error = %v, wantErr %v", tt.threshold, err, tt.wantErr)
		}
	}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
