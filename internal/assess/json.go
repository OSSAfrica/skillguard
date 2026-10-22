package assess

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"skillguard/internal/verify"
	"strings"
	"time"
	"unicode/utf8"
)

// StrictJSON rejects duplicate keys too: two consumers must not interpret one
// policy/request differently. Errors never echo untrusted input or secrets.
func StrictJSON(data []byte, dst any) error {
	if len(data) > MaxBytes || !utf8.Valid(data) || !uniqueJSON(data) {
		return errors.New("invalid or oversized JSON")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(dst) != nil || d.Decode(new(any)) != io.EOF {
		return errors.New("invalid JSON schema")
	}
	return nil
}

func uniqueJSON(data []byte) bool {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var value func(int) bool
	value = func(depth int) bool {
		if depth > 64 {
			return false
		}
		t, e := d.Token()
		if e != nil {
			return false
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return true
		}
		switch delim {
		case '{':
			keys := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return false
				}
				key, ok := k.(string)
				if !ok || keys[key] {
					return false
				}
				keys[key] = true
				if !value(depth + 1) {
					return false
				}
			}
		case '[':
			for d.More() {
				if !value(depth + 1) {
					return false
				}
			}
		default:
			return false
		}
		_, e = d.Token()
		return e == nil
	}
	return value(0) && func() bool { _, e := d.Token(); return e == io.EOF }()
}

func fingerprint(value any) string {
	data, _ := json.Marshal(value)
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:])
}

var safeID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$`)
var hashID = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

func DecodeRequest(data []byte) (Request, error) {
	var r Request
	if err := StrictJSON(data, &r); err != nil {
		return r, err
	}
	invalid := errors.New("invalid action request")
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(data, &fields)
	for _, key := range []string{"schema_version", "target_root", "cwd", "action", "environment", "context_profile", "inputs"} {
		if _, ok := fields[key]; !ok {
			return r, invalid
		}
	}
	if r.SchemaVersion != 1 || !filepath.IsAbs(r.TargetRoot) || filepath.Clean(r.TargetRoot) != r.TargetRoot || !filepath.IsAbs(r.CWD) || filepath.Clean(r.CWD) != r.CWD || r.Environment == nil || r.Inputs == nil || len(r.Environment) > 128 || len(r.Inputs) > 32 || len(r.Provenance) > 16 || (r.ContextProfile != "" && !safeID.MatchString(r.ContextProfile)) {
		return r, invalid
	}
	if !validEnvironment(r.Environment) {
		return r, invalid
	}

	if !validAction(r.Action) {
		return r, invalid
	}

	rel, err := filepath.Rel(r.TargetRoot, r.CWD)
	if err != nil || (rel != "." && !filepath.IsLocal(rel)) {
		return r, invalid
	}
	seen := map[string]bool{}
	for _, in := range r.Inputs {
		if !validInputPath(in.Path) || seen[in.Path] {
			return r, invalid
		}
		seen[in.Path] = true
		switch in.Kind {
		case "requirements", "constraints", "manifest", "lockfile", "config":
		default:
			return r, invalid
		}
	}
	for _, p := range r.Provenance {
		if len(p) > 2048 {
			return r, invalid
		}
	}
	return r, nil
}

func validEnvironment(env map[string]string) bool {
	for k, v := range env {
		if k == "" || strings.ContainsAny(k, "=\x00") || len(k) > 256 || len(v) > 8192 || strings.ContainsRune(v, 0) {
			return false
		}
	}
	return true
}

func validAction(action Action) bool {
	switch action.Mode {
	case "argv":
		if len(action.Argv) == 0 || len(action.Argv) > 512 || action.Command != "" {
			return false
		}
		for _, a := range action.Argv {
			if len(a) > 8192 || strings.ContainsRune(a, 0) {
				return false
			}
		}
	case "bash":
		if action.Command == "" || len(action.Command) > 64<<10 || action.Argv != nil || strings.ContainsRune(action.Command, 0) {
			return false
		}
	default:
		return false
	}
	return true
}

func validInputPath(p string) bool {
	return !strings.ContainsFunc(p, func(r rune) bool { return r < 32 || r == 127 }) && p != "" && len(p) <= 512 && filepath.IsLocal(p) && filepath.Clean(p) == p && !strings.ContainsAny(p, ":\\\x00")
}

// LoadPolicy requires a regular operator file outside the target tree, resolving
// symlinks on both sides. The harness must also deny target writes to this file.
func LoadPolicy(filename, cwd string) (Policy, error) {
	var p Policy
	real, err := filepath.EvalSymlinks(filename)
	if err != nil {
		return p, errors.New("policy unavailable")
	}
	real, err = filepath.Abs(real)
	if err != nil {
		return p, errors.New("policy unavailable")
	}
	target, err := filepath.EvalSymlinks(cwd)
	if err != nil {
		return p, errors.New("working directory unavailable")
	}
	rel, err := filepath.Rel(target, real)
	if err != nil || filepath.IsLocal(rel) || rel == "." {
		return p, errors.New("policy must be outside the target tree")
	}
	f, err := os.Open(real) // #nosec G304 -- explicitly selected operator policy outside target
	if err != nil {
		return p, errors.New("policy unavailable")
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > MaxBytes {
		return p, errors.New("invalid policy file")
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxBytes+1))
	if err != nil {
		return p, errors.New("policy unreadable")
	}
	if err = StrictJSON(data, &p); err != nil {
		return p, errors.New("invalid action policy JSON")
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(data, &fields)
	if _, ok := fields["require_metadata"]; !ok {
		return p, errors.New("policy must explicitly select metadata requirement")
	}
	return p, p.validate()
}

func (p Policy) validate() error {
	invalid := errors.New("invalid action policy")
	if p.IsolatedProfiles == nil || p.ReviewedActions == nil || p.SchemaVersion != 1 || !safeID.MatchString(p.ID) || !safeID.MatchString(p.Version) || p.MaxAgeSeconds < 1 || p.MaxAgeSeconds > 300 || len(p.IsolatedProfiles) > 32 || len(p.ReviewedActions) > 256 || len(p.ProhibitedPackages) > 256 || len(p.ProhibitedArtifactHashes) > 256 {
		return invalid
	}
	for _, id := range p.IsolatedProfiles {
		if !safeID.MatchString(id) {
			return invalid
		}
	}
	if !validBaselines(p.ReviewedActions) {
		return invalid
	}

	if !validPackageRules(p.ProhibitedPackages) {
		return invalid
	}

	for _, h := range p.ProhibitedArtifactHashes {
		if !validArtifactHash(h) {
			return invalid
		}
	}
	if p.RequireMetadata && p.Verification == nil {
		return invalid
	}
	if p.Verification != nil {
		v, err := verify.New(*p.Verification, verify.Options{})
		if err != nil {
			return invalid
		}
		v.Close()
	}
	return nil
}

func validPackageRules(rules []PackageRule) bool {
	for _, r := range rules {
		if (r.Ecosystem != "npm" && r.Ecosystem != "pypi") || r.Name == "" || len(r.Name) > 214 || len(r.Version) > 128 {
			return false
		}
		if r.Version != "" && ((r.Ecosystem == "npm" && !npmExactVersion.MatchString(r.Version)) || (r.Ecosystem == "pypi" && !pythonPolicyVersion.MatchString(r.Version))) {
			return false
		}
	}
	return true
}

func validBaselines(baselines []Baseline) bool {
	for _, b := range baselines {
		if !hashID.MatchString(b.SubjectFingerprint) || !hashID.MatchString(b.ContextFingerprint) || !safeID.MatchString(b.ReviewID) || b.ExpiresAt.IsZero() {
			return false
		}
	}
	return true
}

func newResponse(version string, now time.Time) Response {
	return Response{SchemaVersion: 1, EngineVersion: version, RulesetVersion: RulesetVersion, AssessedAt: now.UTC(), ExpiresAt: now.UTC(), Status: "error", Decision: "deny", EvidenceTrust: "untrusted_data", Rules: []Rule{}, Checks: []Check{}, Inputs: []InputFact{}, Dependencies: []DependencyFact{}}
}

func ErrorResponse(version, code string, now time.Time) Response {
	r := newResponse(version, now)
	r.Rules = append(r.Rules, Rule{ID: code, Effect: "deny", Message: "Assessment could not be completed.", Remediation: "Correct the request or operator configuration and reassess."})
	r.Checks = append(r.Checks, Check{ID: "request_policy", Required: true, Status: "error"})
	return r
}
