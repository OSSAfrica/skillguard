// Package verify performs explicitly authorized metadata lookups. It never
// installs packages, follows artifact URLs, or treats existence as legitimacy.
package verify

import (
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
)

type Policy struct {
	SchemaVersion   int        `json:"schema_version"`
	Registries      []Registry `json:"registries"`
	DNSHosts        []string   `json:"dns_hosts,omitempty"`
	TimeoutSeconds  int        `json:"timeout_seconds,omitempty"`
	MaxRequests     int        `json:"max_requests,omitempty"`
	CacheTTLSeconds int        `json:"cache_ttl_seconds,omitempty"`
	MinIntervalMS   int        `json:"min_interval_ms,omitempty"`
}

type Registry struct {
	ID                  string   `json:"id"`
	Ecosystem           string   `json:"ecosystem"`
	MetadataURL         string   `json:"metadata_url"`
	InstallURL          string   `json:"install_url"`
	Default             bool     `json:"default,omitempty"`
	Packages            []string `json:"packages"`
	AuthEnv             string   `json:"auth_env,omitempty"`
	AllowPrivateNetwork bool     `json:"allow_private_network,omitempty"`
}

var identifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]{0,127}$`)
var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
var npmName = regexp.MustCompile(`^(?:@[a-z0-9._~-]+/)?[a-z0-9][a-z0-9._~-]*$`)
var pythonName = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$`)
var pythonNormalize = regexp.MustCompile(`[-_.]+`)

func LoadPolicy(filename string) (Policy, error) {
	var p Policy
	f, err := os.Open(filename) // #nosec G304 -- explicitly selected operator configuration, never auto-discovered
	if err != nil {
		return p, errors.New("could not open verification policy")
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return p, errors.New("verification policy must be a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, 64<<10+1))
	if err != nil || len(data) > 64<<10 {
		return p, errors.New("verification policy exceeds its read limit")
	}
	d := json.NewDecoder(strings.NewReader(string(data)))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF {
		return p, errors.New("invalid verification policy JSON")
	}
	if err := p.validate(); err != nil {
		return p, err
	}
	return p, nil
}

func (p *Policy) validate() error {
	invalid := errors.New("invalid verification policy: use schema 1, explicit HTTPS registries/package allowlists, and bounded limits")
	if p.SchemaVersion != 1 || len(p.Registries) > 16 || len(p.DNSHosts) > 128 {
		return invalid
	}
	if p.TimeoutSeconds == 0 {
		p.TimeoutSeconds = 5
	}
	if p.MaxRequests == 0 {
		p.MaxRequests = 64
	}
	if p.CacheTTLSeconds == 0 {
		p.CacheTTLSeconds = 300
	}
	if p.MinIntervalMS == 0 {
		p.MinIntervalMS = 100
	}
	if !p.validLimits() {
		return invalid
	}
	ids, defaults, installs := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for i := range p.Registries {
		r := &p.Registries[i]
		if !r.validate() || ids[r.ID] {
			return invalid
		}
		ids[r.ID] = true
		if r.Default && defaults[r.Ecosystem] {
			return invalid
		}
		defaults[r.Ecosystem] = defaults[r.Ecosystem] || r.Default
		if installs[r.Ecosystem+r.InstallURL] {
			return invalid
		}
		installs[r.Ecosystem+r.InstallURL] = true
	}
	for i, host := range p.DNSHosts {
		if host == "" || len(host) > 253 || strings.ContainsAny(host, "/:@?#*[]\\ \t\r\n") {
			return invalid
		}
		p.DNSHosts[i] = strings.ToLower(strings.TrimSuffix(host, "."))
	}
	return nil
}

func (p Policy) validLimits() bool {
	return p.TimeoutSeconds >= 1 && p.TimeoutSeconds <= 30 && p.MaxRequests >= 1 && p.MaxRequests <= 256 && p.CacheTTLSeconds >= 1 && p.CacheTTLSeconds <= 3600 && p.MinIntervalMS >= 1 && p.MinIntervalMS <= 10000
}

func (r *Registry) validate() bool {
	if !identifier.MatchString(r.ID) || (r.Ecosystem != "npm" && r.Ecosystem != "pypi") || len(r.Packages) == 0 || len(r.Packages) > 256 {
		return false
	}
	metadata, ok := canonicalEndpoint(r.MetadataURL)
	if !ok {
		return false
	}
	install, ok := canonicalEndpoint(r.InstallURL)
	if !ok {
		return false
	}
	r.MetadataURL, r.InstallURL = metadata, install
	if r.AuthEnv != "" && !envName.MatchString(r.AuthEnv) {
		return false
	}
	for _, pattern := range r.Packages {
		if pattern == "" || len(pattern) > 256 || strings.ContainsAny(pattern, "?[]\\") {
			return false
		}
		if _, err := path.Match(pattern, "test"); err != nil {
			return false
		}
	}
	return true
}

func canonicalEndpoint(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || len(raw) > 512 {
		return "", false
	}
	if strings.TrimRight(u.Path, "/") != strings.TrimRight(path.Clean("/"+strings.TrimPrefix(u.Path, "/")), "/") || u.RawPath != "" {
		return "", false
	}
	u.Host = strings.ToLower(u.Host)
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return u.String(), true
}

func normalizeName(ecosystem, name string) (string, bool) {
	if ecosystem == "npm" {
		return name, len(name) <= 214 && npmName.MatchString(name)
	}
	if ecosystem == "pypi" && len(name) <= 214 && pythonName.MatchString(name) {
		return pythonNormalize.ReplaceAllString(strings.ToLower(name), "-"), true
	}
	return "", false
}

func allowedPackage(r Registry, name string) bool {
	for _, pattern := range r.Packages {
		if pattern == "*" {
			return true
		}
		if r.Ecosystem == "pypi" {
			pattern = pythonNormalize.ReplaceAllString(strings.ToLower(pattern), "-")
		}
		if matched, _ := path.Match(pattern, name); matched {
			return true
		}
	}
	return false
}
