package extract

import (
	"net/url"
	"regexp"
	"strings"

	"skillguard/internal/model"
)

var (
	npmName         = regexp.MustCompile(`^(?:@[a-z0-9._~-]+/)?[a-z0-9][a-z0-9._~-]*$`)
	pythonSpec      = regexp.MustCompile(`^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)(\[[A-Za-z0-9._,-]+\])?\s*((?:(?:===|==|~=|!=|<=|>=|<|>)[A-Za-z0-9.*+!_-]+)(?:\s*,\s*(?:===|==|~=|!=|<=|>=|<|>)[A-Za-z0-9.*+!_-]+)*)?$`)
	pythonNormalize = regexp.MustCompile(`[-_.]+`)
	npmVersion      = regexp.MustCompile(`^[A-Za-z0-9.*^~<>=|+ -]+$`)
)

// SafeSource removes URL credentials and query/fragment data. Never use source
// labels as local paths or network requests; they are display-only identities.
func SafeSource(source string) string {
	u, err := url.Parse(source)
	if strings.Contains(source, "://") && (err != nil || u.Host == "") {
		return "[invalid URL]"
	}
	if err == nil && u.Scheme != "" && u.Host != "" {
		u.User, u.RawQuery, u.Fragment = nil, "", ""
		u.ForceQuery = false
		source = u.String()
	}
	return bounded(source, 512)
}

func bounded(value string, limit int) string {
	// Escape controls in untrusted display strings, including terminal escapes.
	value = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return '\ufffd'
		}
		return r
	}, value)
	if len(value) > limit {
		return value[:limit] + "…"
	}
	return value
}

func dependency(ecosystem, spec string) (model.Dependency, bool) {
	d := model.Dependency{Ecosystem: ecosystem, Source: "registry"}
	if len(spec) == 0 || len(spec) > 1024 {
		d.Source = "unresolved"
		return d, false
	}
	if source := nonRegistrySource(spec); source != "" {
		d.Source, d.Specifier = source, SafeSource(spec)
		return d, true
	}
	if ecosystem == "npm" {
		return npmDependency(spec)
	}
	if name, target, ok := strings.Cut(spec, "@"); ok {
		match := pythonSpec.FindStringSubmatch(strings.TrimSpace(name))
		if match != nil && nonRegistrySource(strings.TrimSpace(target)) != "" {
			d.Name = pythonNormalize.ReplaceAllString(strings.ToLower(match[1]), "-")
			d.Source = nonRegistrySource(strings.TrimSpace(target))
			d.Specifier = SafeSource(strings.TrimSpace(target))
			d.Extras = pythonExtras(match[2])
			return d, true
		}
	}
	match := pythonSpec.FindStringSubmatch(strings.TrimSpace(spec))
	if match == nil {
		d.Source = "unresolved"
		return d, false
	}
	d.Name = pythonNormalize.ReplaceAllString(strings.ToLower(match[1]), "-")
	d.Specifier = match[2] + match[3]
	d.Extras = pythonExtras(match[2])
	return d, true
}

func pythonExtras(value string) []string {
	if value == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(strings.TrimPrefix(value, "["), "]"), ",")
}

func npmDependency(spec string) (model.Dependency, bool) {
	d := model.Dependency{Ecosystem: "npm", Source: "registry"}
	name, version := spec, ""
	if at := strings.LastIndex(spec, "@"); at > 0 {
		name, version = spec[:at], spec[at+1:]
	}
	// Aliases refer to the target package, not an independently published alias.
	if index := strings.Index(spec, "@npm:"); index > 0 {
		alias := spec[:index]
		target := spec[index+5:]
		if !npmName.MatchString(alias) || strings.Contains(target, "npm:") {
			d.Source = "unresolved"
			return d, false
		}
		d, ok := npmDependency(target)
		d.Alias = alias
		return d, ok
	}
	// A package name can prefix a tarball or Git URL.
	if index := strings.Index(spec, "@"); index > 0 && nonRegistrySource(spec[index+1:]) != "" {
		name, version = spec[:index], spec[index+1:]
	} else if strings.HasPrefix(spec, "@") {
		if index := strings.Index(spec[1:], "@"); index >= 0 {
			name, version = spec[:index+1], spec[index+2:]
		}
	}
	if !npmName.MatchString(name) {
		d.Source = "unresolved"
		return d, false
	}
	d.Name, d.Specifier = name, version
	if source := nonRegistrySource(version); source != "" {
		d.Source, d.Specifier = source, SafeSource(version)
		return d, true
	}
	if version != "" && !npmVersion.MatchString(version) {
		d.Specifier, d.Source = "", "unresolved"
		return d, false
	}
	return d, true
}

func nonRegistrySource(spec string) string {
	lower := strings.ToLower(spec)
	if strings.HasPrefix(lower, "git+") || strings.HasPrefix(lower, "git:") || strings.HasPrefix(lower, "git@") || strings.HasPrefix(lower, "github:") || strings.HasPrefix(lower, "gitlab:") || strings.HasPrefix(lower, "bitbucket:") {
		return "git"
	}
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return "url"
	}
	if strings.HasPrefix(spec, ".") || strings.HasPrefix(spec, "/") || strings.HasPrefix(lower, "file:") || strings.HasPrefix(lower, "workspace:") {
		return "local"
	}
	if !strings.ContainsAny(spec, " @") && (strings.HasSuffix(lower, ".whl") || strings.HasSuffix(lower, ".tgz") || strings.HasSuffix(lower, ".tar.gz")) {
		return "local"
	}
	if strings.Contains(spec, "/") && !strings.HasPrefix(spec, "@") && !strings.Contains(spec, ":") {
		return "git"
	}
	return ""
}
