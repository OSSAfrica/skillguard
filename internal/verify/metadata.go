package verify

import (
	"bytes"
	"encoding/json"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"skillguard/internal/extract"
)

type Metadata struct {
	State, Reason, VersionState, Version, Repository, Provenance string
	PublishedAt                                                  *time.Time
}

// RegistryClient adapters interpret metadata only; transport authorization,
// bounds, and authentication remain centralized in Fetcher.
type RegistryClient interface {
	MetadataPath(string) string
	Inspect([]byte, string, string) Metadata
}

type NPMClient struct{}
type PyPIClient struct{}

func (NPMClient) MetadataPath(name string) string  { return "/" + url.PathEscape(name) }
func (PyPIClient) MetadataPath(name string) string { return "/" + url.PathEscape(name) + "/json" }

func decodeMetadata(data []byte, target any) bool {
	d := json.NewDecoder(bytes.NewReader(data))
	return d.Decode(target) == nil && d.Decode(new(any)) == io.EOF
}

type npmVersionInfo struct {
	Version    string          `json:"version"`
	Repository json.RawMessage `json:"repository"`
	Dist       struct {
		Attestations json.RawMessage `json:"attestations"`
	} `json:"dist"`
}

func (NPMClient) Inspect(data []byte, name, spec string) Metadata {
	var doc struct {
		Name       string                    `json:"name"`
		Versions   map[string]npmVersionInfo `json:"versions"`
		Tags       map[string]string         `json:"dist-tags"`
		Time       map[string]string         `json:"time"`
		Repository json.RawMessage           `json:"repository"`
	}
	if !decodeMetadata(data, &doc) || doc.Name != name || doc.Versions == nil {
		return malformed()
	}
	m := Metadata{State: "found", VersionState: "not_requested", Provenance: "not_supplied", Repository: repositoryURL(doc.Repository)}
	version, state := npmRequestedVersion(spec, doc.Tags)
	m.VersionState = state
	if spec == "" {
		version = doc.Tags["latest"]
	}
	if state == "unsupported_specifier" || state == "missing" {
		return m
	}
	if version == "" {
		return m
	}
	if !npmPublished.MatchString(version) {
		return malformed()
	}
	selected, ok := doc.Versions[version]
	if !ok {
		if spec != "" {
			m.VersionState = "missing"
		}
		return m
	}
	if selected.Version != version || len(version) > 128 {
		return malformed()
	}
	m.Version = version
	if spec != "" {
		m.VersionState = "found"
	}
	m.PublishedAt = parseTime(doc.Time[version])
	if repo := repositoryURL(selected.Repository); repo != "" {
		m.Repository = repo
	}
	var attestation struct {
		URL string `json:"url"`
	}
	if json.Unmarshal(selected.Dist.Attestations, &attestation) == nil && safeClaimURL(attestation.URL) != "" {
		m.Provenance = "claimed_attestation_not_verified"
	}
	return m
}

var npmExact = regexp.MustCompile(`^v?(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?$`)
var npmPublished = regexp.MustCompile(`^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)
var npmTag = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._-]{0,127}$`)

func npmRequestedVersion(spec string, tags map[string]string) (string, string) {
	if spec == "" {
		return "", "not_requested"
	}
	if npmExact.MatchString(spec) {
		return strings.TrimPrefix(spec, "v"), "found"
	}
	if npmTag.MatchString(spec) {
		version, ok := tags[spec]
		if !ok {
			return "", "missing"
		}
		if !npmPublished.MatchString(version) {
			return "", "unsupported_specifier"
		}
		return version, "found"
	}
	return "", "unsupported_specifier"
}

type pypiFile struct {
	Uploaded string `json:"upload_time_iso_8601"`
}

func (PyPIClient) Inspect(data []byte, name, spec string) Metadata {
	var doc struct {
		Info struct {
			Name        string            `json:"name"`
			Version     string            `json:"version"`
			ProjectURLs map[string]string `json:"project_urls"`
		} `json:"info"`
		Releases map[string][]pypiFile `json:"releases"`
	}
	if !decodeMetadata(data, &doc) || doc.Releases == nil {
		return malformed()
	}
	canonical, ok := normalizeName("pypi", doc.Info.Name)
	if !ok || canonical != name {
		return malformed()
	}
	m := Metadata{State: "found", VersionState: "not_requested", Provenance: "not_checked"}
	for _, key := range []string{"Source", "Source Code", "Repository"} {
		if value := safeClaimURL(doc.Info.ProjectURLs[key]); value != "" {
			m.Repository = value
			break
		}
	}
	if strings.HasPrefix(spec, "[") {
		end := strings.Index(spec, "]")
		if end < 0 {
			m.VersionState = "unsupported_specifier"
			return m
		}
		spec = spec[end+1:]
	}
	version, state := pypiRequestedVersion(spec, doc.Releases)
	m.VersionState = state
	if spec == "" {
		version = doc.Info.Version
	}
	if state == "unsupported_specifier" || state == "missing" {
		return m
	}
	files, ok := doc.Releases[version]
	if !ok {
		if spec != "" {
			m.VersionState = "missing"
		}
		return m
	}
	if !safeVersion.MatchString(version) {
		return malformed()
	}
	m.Version = version
	for _, file := range files {
		if uploaded := parseTime(file.Uploaded); uploaded != nil && (m.PublishedAt == nil || uploaded.Before(*m.PublishedAt)) {
			m.PublishedAt = uploaded
		}
	}
	return m
}

var stablePython = regexp.MustCompile(`^(?:([0-9]+)!)?([0-9]+(?:\.[0-9]+)*)$`)
var safeVersion = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+!-]{0,127}$`)

func pypiRequestedVersion(spec string, releases map[string][]pypiFile) (string, string) {
	if spec == "" {
		return "", "not_requested"
	}
	if strings.HasPrefix(spec, "===") {
		key := strings.TrimPrefix(spec, "===")
		if key == "" || len(key) > 128 || strings.ContainsAny(key, "*, \t\r\n") {
			return "", "unsupported_specifier"
		}
		if _, ok := releases[key]; ok {
			return key, "found"
		}
		return "", "missing"
	}
	if !strings.HasPrefix(spec, "==") || strings.ContainsAny(spec, "*, \t\r\n") {
		return "", "unsupported_specifier"
	}
	key := strings.TrimPrefix(spec, "==")
	if _, ok := releases[key]; ok {
		return key, "found"
	}
	canonical, ok := canonicalStablePython(key)
	if !ok {
		return "", "unsupported_specifier"
	}
	// Stable release equality tolerates trailing zeros and local labels. Full
	// PEP 440 range/prerelease resolution is explicitly outside this adapter.
	keys := make([]string, 0, len(releases))
	for k := range releases {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, candidate := range keys {
		public, _, _ := strings.Cut(candidate, "+")
		if other, ok := canonicalStablePython(public); ok && other == canonical {
			return candidate, "found"
		}
	}
	return "", "missing"
}

func canonicalStablePython(version string) (string, bool) {
	match := stablePython.FindStringSubmatch(strings.TrimPrefix(strings.ToLower(version), "v"))
	if match == nil {
		return "", false
	}
	epoch := strings.TrimLeft(match[1], "0")
	if epoch == "" {
		epoch = "0"
	}
	parts := strings.Split(match[2], ".")
	for i := range parts {
		parts[i] = strings.TrimLeft(parts[i], "0")
		if parts[i] == "" {
			parts[i] = "0"
		}
	}
	for len(parts) > 1 && parts[len(parts)-1] == "0" {
		parts = parts[:len(parts)-1]
	}
	return epoch + "!" + strings.Join(parts, "."), true
}

func malformed() Metadata {
	return Metadata{State: "malformed_response", Reason: "invalid_registry_metadata", VersionState: "unknown", Provenance: "not_checked"}
}

func parseTime(raw string) *time.Time {
	if len(raw) > 64 {
		return nil
	}
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return nil
	}
	t = t.UTC()
	return &t
}

func repositoryURL(raw json.RawMessage) string {
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return safeClaimURL(text)
	}
	var doc struct {
		URL string `json:"url"`
	}
	if json.Unmarshal(raw, &doc) == nil {
		return safeClaimURL(doc.URL)
	}
	return ""
}

func safeClaimURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || (u.Scheme != "https" && u.Scheme != "http" && u.Scheme != "git+https" && u.Scheme != "git+ssh") {
		return ""
	}
	return extract.SafeSource(raw)
}
