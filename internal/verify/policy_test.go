package verify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOperatorPolicyValidationAndDefaults(t *testing.T) {
	file := filepath.Join(t.TempDir(), "policy.json")
	valid := `{"schema_version":1,"registries":[{"id":"public-npm","ecosystem":"npm","metadata_url":"https://registry.npmjs.org/","install_url":"https://registry.npmjs.org/","default":true,"packages":["helper","@company/*"]}]}`
	if err := os.WriteFile(file, []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := LoadPolicy(file)
	if err != nil || p.MaxRequests != 64 || p.TimeoutSeconds != 5 || p.CacheTTLSeconds != 300 || p.MinIntervalMS != 100 {
		t.Fatalf("policy defaults = %+v, %v", p, err)
	}
	if !allowedPackage(p.Registries[0], "@company/private-helper") || allowedPackage(p.Registries[0], "other-company-private") {
		t.Fatal("package allowlist mismatch")
	}
	for _, bad := range []string{
		strings.Replace(valid, "https://registry.npmjs.org/", "http://registry.npmjs.org/", 1),
		strings.Replace(valid, "https://registry.npmjs.org/", "https://user:secret@registry.npmjs.org/", 1),
		strings.Replace(valid, "https://registry.npmjs.org/", "https://registry.npmjs.org/?token=secret", 1),
		strings.Replace(valid, "https://registry.npmjs.org/", "https://registry.npmjs.org/a/../", 1),
		strings.Replace(valid, `"schema_version":1`, `"schema_version":1,"max_requests":999`, 1),
		strings.Replace(valid, `"schema_version":1`, `"schema_version":1,"unknown_secret":"secret"`, 1),
		valid + "{}", strings.Repeat(" ", 64<<10+1),
	} {
		if err := os.WriteFile(file, []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPolicy(file); err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatalf("invalid policy accepted or secret leaked: %v", err)
		}
	}
}
