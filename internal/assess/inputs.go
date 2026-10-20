package assess

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"skillguard/internal/extract"
	"skillguard/internal/model"
)

type inputSet struct {
	data  map[string][]byte
	kinds map[string]string
}

func (e *evaluation) readInputs() inputSet {
	result := inputSet{data: map[string][]byte{}, kinds: map[string]string{}}
	root, err := os.OpenRoot(e.request.CWD)
	if err != nil {
		e.gap("SG_INPUT_BOUNDARY", "The working directory could not be opened.")
		return result
	}
	defer func() { _ = root.Close() }()
	total := 0
	for _, in := range e.request.Inputs {
		fact := InputFact{Path: extract.SafeSource(in.Path), Kind: in.Kind, Status: "unavailable"}
		data, ok := readInput(root, in.Path)
		total += len(data)
		if ok && total <= 4*MaxBytes {
			fact.SHA256 = bytesHash(data)
			fact.Status = "read"
			result.data[in.Path] = data
			result.kinds[in.Path] = in.Kind
		} else {
			e.gap("SG_INPUT_UNAVAILABLE", "A declared dependency/configuration input could not be read within its boundary and limits.")
		}
		e.response.Inputs = append(e.response.Inputs, fact)
	}
	// These files alter installation even when the agent did not mention them.
	// A stat operation discovers presence only; contents are read solely if declared.
	for _, name := range []string{"package.json", "package-lock.json", "npm-shrinkwrap.json", ".npmrc", "pip.conf", "pip.ini", "pyproject.toml", "setup.cfg", "setup.py"} {
		_, err := root.Lstat(name)
		if !os.IsNotExist(err) && result.kinds[name] == "" {
			e.gap("SG_INPUT_UNDECLARED", "An installation-relevant file was not declared or its absence could not be established.")
		}
	}
	sort.Slice(e.response.Inputs, func(i, j int) bool { return e.response.Inputs[i].Path < e.response.Inputs[j].Path })
	return result
}

func readInput(root *os.Root, name string) ([]byte, bool) {
	f, err := openInput(root, name)
	if err != nil {
		return nil, false
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > MaxBytes {
		return nil, false
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxBytes+1))
	return data, err == nil && len(data) <= MaxBytes
}

func (e *evaluation) resolve(c *model.DocumentCommand, inputs inputSet) {
	used := map[string]bool{}
	for _, ref := range c.Inputs {
		kind := inputs.kinds[ref.Path]
		if kind == "" || kind != ref.Kind || inputs.data[ref.Path] == nil {
			e.gap("SG_INPUT_UNDECLARED", "A command input is absent or its declared kind does not match.")
			continue
		}
		used[ref.Path] = true
	}
	original := append([]model.Dependency(nil), c.Dependencies...)
	c.Dependencies = nil
	for _, dep := range original {
		e.addDependency(c, dep, "action", 1, nil)
	}
	switch c.Tool {
	case "pip", "pip3":
		wheelsOnly := false
		for _, o := range c.Options {
			if o.Name == "--only-binary" && o.Value == ":all:" {
				wheelsOnly = true
			}
		}
		if !wheelsOnly {
			e.deny("SG_SOURCE_BUILDS", "pip source builds and their unresolved build dependencies are prohibited; require --only-binary=:all:.")
		}
		if !hasOption(*c, "--no-deps") {
			e.gap("SG_TRANSITIVE_UNRESOLVED", "pip dependency resolution requires --no-deps and a fully reviewed explicit dependency set in this version.")
		}
		for _, ref := range c.Inputs {
			if ref.Kind == "requirements" && used[ref.Path] {
				e.requirements(c, ref.Path, inputs.data[ref.Path])
			} else if ref.Kind != "config" {
				e.gap("SG_INPUT_UNSUPPORTED", "Only the documented flat requirements format is supported for pip inputs.")
			}
		}
	case "npm":
		if hasOption(*c, "--global") || hasOption(*c, "-g") {
			e.gap("SG_INSTALL_CONTEXT", "Global installation context is not supported.")
		}
		if !hasOption(*c, "--ignore-scripts") {
			e.deny("SG_INSTALL_SCRIPTS", "npm installation scripts are prohibited by this ruleset.")
		}
		if c.Operation != "ci" {
			e.gap("SG_TRANSITIVE_UNRESOLVED", "npm actions require npm ci and a supported complete lockfile in this version.")
		} else {
			used["package.json"] = true
			used["package-lock.json"] = true
			e.npmLock(c, inputs)
		}
	default:
		e.deny("SG_PACKAGE_EXECUTION", "Downloading or executing a package/tool is outside the permitted install-only action contract.")
	}
	for _, name := range sortedInputNames(inputs) {
		kind := inputs.kinds[name]
		if kind == "config" {
			e.config(c, name, inputs.data[name])
			used[name] = true
		}
		if !used[name] {
			e.gap("SG_INPUT_UNUSED", "A declared input is not resolved as part of this action.")
		}
	}
	c.Inputs = nil // All command inputs are now represented by facts and gaps.
	if len(c.Dependencies) == 0 {
		e.gap("SG_DEPENDENCIES_EMPTY", "No concrete dependency set was resolved.")
	}
}

func hasOption(c model.DocumentCommand, name string) bool {
	for _, o := range c.Options {
		if o.Name == name {
			return true
		}
	}
	return false
}

func (e *evaluation) addDependency(c *model.DocumentCommand, dep model.Dependency, source string, line int, hashes []string) {
	if len(e.response.Dependencies) >= 512 {
		e.gap("SG_DEPENDENCY_LIMIT", "Dependency resolution exceeded the 512-entry limit.")
		return
	}
	loc := model.SourceSpan{Source: extract.SafeSource(source), StartLine: line, EndLine: line}
	e.response.Dependencies = append(e.response.Dependencies, DependencyFact{Dependency: dep, Location: loc, ArtifactHashes: append([]string{}, hashes...)})
	c.Dependencies = append(c.Dependencies, dep)
	if dep.Source != "registry" || dep.Alias != "" || len(dep.Extras) > 0 {
		e.deny("SG_DEPENDENCY_SOURCE", "Direct, local, Git, alias, or extras sources are not allowed by this ruleset.")
	}
	if !exactVersion(dep) {
		e.review("SG_VERSION_UNPINNED", "A dependency does not identify a supported exact version.")
	}
	if len(hashes) == 0 {
		e.mutable = true
	}
	for _, h := range hashes {
		for _, blocked := range e.policy.ProhibitedArtifactHashes {
			if h == blocked {
				e.deny("SG_ARTIFACT_PROHIBITED", "A dependency artifact hash is prohibited by operator policy.")
			}
		}
	}
	for _, rule := range e.policy.ProhibitedPackages {
		if dep.Ecosystem == rule.Ecosystem && normalizeName(dep.Ecosystem, dep.Name) == normalizeName(rule.Ecosystem, rule.Name) && (rule.Version == "" || strings.TrimPrefix(dep.Specifier, "==") == rule.Version || dep.Specifier == rule.Version) {
			e.deny("SG_PACKAGE_PROHIBITED", "A dependency is prohibited by operator policy.")
		}
	}
}

var stableVersion = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){1,3}$`)

func exactVersion(dep model.Dependency) bool {
	spec := dep.Specifier
	if dep.Ecosystem == "pypi" {
		if !strings.HasPrefix(spec, "==") || strings.HasPrefix(spec, "===") {
			return false
		}
		spec = strings.TrimPrefix(spec, "==")
	}
	return stableVersion.MatchString(spec)
}

var pythonNameRun = regexp.MustCompile(`[-_.]+`)

func normalizeName(eco, name string) string {
	if eco == "pypi" {
		return pythonNameRun.ReplaceAllString(strings.ToLower(name), "-")
	}
	return name
}

func validArtifactHash(h string) bool {
	if strings.HasPrefix(h, "sha256:") {
		b, err := hex.DecodeString(strings.TrimPrefix(h, "sha256:"))
		return err == nil && len(b) == 32 && strings.ToLower(h) == h
	}
	if strings.HasPrefix(h, "sha512-") {
		b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(h, "sha512-"))
		return err == nil && len(b) == 64
	}
	return false
}

func (e *evaluation) requirements(c *model.DocumentCommand, name string, data []byte) {
	// Deliberately reject includes, markers, URLs, options and extras instead of
	// approximating pip's full grammar. Continued hash lines are supported.
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	text = strings.ReplaceAll(text, "\\\n", " ")
	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Buffer(make([]byte, 4096), MaxBytes)
	line := 0
	for scanner.Scan() {
		line++
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		words := strings.Fields(raw)
		if len(words) == 0 {
			continue
		}
		if strings.ContainsAny(words[0], ";[]@/") || strings.HasPrefix(words[0], "-") {
			e.gap("SG_REQUIREMENTS_SYNTAX", "A requirements entry uses unsupported syntax.")
			continue
		}
		x := extract.Action([]string{"pip", "install", words[0]}, "")
		if x.Status != "complete" || len(x.Commands) != 1 || len(x.Commands[0].Dependencies) != 1 {
			e.gap("SG_REQUIREMENTS_SYNTAX", "A requirements entry could not be resolved.")
			continue
		}
		hashes := []string{}
		valid := true
		for _, word := range words[1:] {
			h := strings.TrimPrefix(word, "--hash=")
			if h == word || !strings.HasPrefix(h, "sha256:") || !validArtifactHash(h) {
				valid = false
				break
			}
			hashes = append(hashes, h)
		}
		if !valid {
			e.gap("SG_REQUIREMENTS_SYNTAX", "Only exact requirements with optional SHA-256 hashes are supported.")
			continue
		}
		if hasOption(*c, "--require-hashes") && len(hashes) == 0 {
			e.deny("SG_HASH_REQUIRED", "A hash-required requirement has no supported artifact hash.")
		}
		if !hasOption(*c, "--require-hashes") {
			hashes = nil
		} // merely writing hashes does not enforce the full install action.
		e.addDependency(c, x.Commands[0].Dependencies[0], name, line, hashes)
	}
	if scanner.Err() != nil {
		e.gap("SG_REQUIREMENTS_LIMIT", "A requirements input exceeds parsing limits.")
	}
}

type npmManifest struct {
	Name                 string            `json:"name"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}
type lockPackage struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Resolved             string            `json:"resolved"`
	Integrity            string            `json:"integrity"`
	Link                 bool              `json:"link"`
	InBundle             bool              `json:"inBundle"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}
type npmLock struct {
	LockfileVersion int                    `json:"lockfileVersion"`
	Packages        map[string]lockPackage `json:"packages"`
}

func (e *evaluation) npmLock(c *model.DocumentCommand, inputs inputSet) {
	manifest, lock := inputs.data["package.json"], inputs.data["package-lock.json"]
	if inputs.kinds["package.json"] != "manifest" || inputs.kinds["package-lock.json"] != "lockfile" || manifest == nil || lock == nil {
		e.gap("SG_LOCKFILE_REQUIRED", "npm ci requires declared package.json and package-lock.json inputs.")
		return
	}
	var m npmManifest
	var l npmLock
	// npm files have extensible schemas; reject duplicate keys but retain unknown
	// fields in the content fingerprint. Unsupported execution fields below fail.
	if !uniqueJSON(manifest) || !uniqueJSON(lock) || json.Unmarshal(manifest, &m) != nil || json.Unmarshal(lock, &l) != nil || l.LockfileVersion != 3 || len(l.Packages) == 0 || len(l.Packages) > 513 {
		e.gap("SG_LOCKFILE_UNSUPPORTED", "Only a bounded package-lock v3 registry dependency tree is supported.")
		return
	}
	root, ok := l.Packages[""]
	if !ok || fingerprint(m.Dependencies) != fingerprint(root.Dependencies) || fingerprint(m.DevDependencies) != fingerprint(root.DevDependencies) || fingerprint(m.OptionalDependencies) != fingerprint(root.OptionalDependencies) {
		e.gap("SG_MANIFEST_LOCK_MISMATCH", "Manifest and lockfile root dependency declarations differ.")
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(manifest, &fields)
	for _, k := range []string{"workspaces", "overrides", "bundledDependencies", "bundleDependencies"} {
		if _, ok := fields[k]; ok {
			e.gap("SG_MANIFEST_UNSUPPORTED", "Manifest uses dependency selection outside this ruleset.")
		}
	}
	if inputs.data["npm-shrinkwrap.json"] != nil {
		e.gap("SG_SHRINKWRAP_UNSUPPORTED", "npm-shrinkwrap precedence is not supported.")
	}
	names := make([]string, 0, len(l.Packages))
	for n := range l.Packages {
		if n != "" {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	for _, key := range names {
		e.npmLockEntry(c, key, l.Packages[key])
	}
}

func (e *evaluation) npmLockEntry(c *model.DocumentCommand, key string, p lockPackage) {
	idx := strings.LastIndex(key, "node_modules/")
	if idx < 0 || !validInputPath(key) || p.Link || p.InBundle {
		e.gap("SG_LOCK_ENTRY_UNSUPPORTED", "A lockfile entry is not a supported installed registry package.")
		return
	}
	name := key[idx+len("node_modules/"):]
	x := extract.Action([]string{"npm", "install", name + "@" + p.Version}, "")
	if x.Status != "complete" || len(x.Commands) != 1 || len(x.Commands[0].Dependencies) != 1 || (p.Name != "" && p.Name != name) {
		e.gap("SG_LOCK_ENTRY_UNSUPPORTED", "A lockfile package name/version could not be interpreted.")
		return
	}
	if !e.allowedArtifactURL(p.Resolved) {
		e.deny("SG_SOURCE_PROHIBITED", "A lockfile artifact is outside the operator-configured registry origins.")
	}
	hashes := strings.Fields(p.Integrity)
	if len(hashes) == 0 {
		e.gap("SG_LOCK_INTEGRITY", "A registry lockfile entry has no artifact integrity.")
	}
	for _, h := range hashes {
		if !strings.HasPrefix(h, "sha512-") || !validArtifactHash(h) {
			e.gap("SG_LOCK_INTEGRITY", "A lockfile integrity entry is not a supported SHA-512 digest.")
			hashes = nil
			break
		}
	}
	e.addDependency(c, x.Commands[0].Dependencies[0], "package-lock.json", 1, hashes)
}

func (e *evaluation) allowedArtifactURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || e.policy.Verification == nil {
		return false
	}
	for _, r := range e.policy.Verification.Registries {
		base, err := url.Parse(r.InstallURL)
		if err == nil && r.Ecosystem == "npm" && strings.EqualFold(base.Host, u.Host) && strings.HasPrefix(u.EscapedPath(), strings.TrimRight(base.EscapedPath(), "/")+"/") {
			return true
		}
	}
	return false
}

func (e *evaluation) config(c *model.DocumentCommand, name string, data []byte) {
	// Only these local source-only files are understood. Authentication, scope
	// overrides, proxies and executable settings require a future resolver.
	if (c.Tool == "npm" && filepath.Base(name) != ".npmrc") || ((c.Tool == "pip" || c.Tool == "pip3") && filepath.Base(name) != "pip.conf" && filepath.Base(name) != "pip.ini") {
		e.gap("SG_CONFIG_UNSUPPORTED", "Configuration format is unsupported.")
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "#") || strings.HasPrefix(s, ";") {
			continue
		}
		if (c.Tool == "pip" || c.Tool == "pip3") && (s == "[global]" || s == "[install]") {
			continue
		}
		key, val, ok := strings.Cut(s, "=")
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		role := "registry"
		want := "registry"
		if c.Tool == "pip" || c.Tool == "pip3" {
			role, want = "index", "index-url"
		}
		if !ok || key != want {
			e.gap("SG_CONFIG_UNSUPPORTED", "Configuration contains settings outside the supported registry-only subset.")
			continue
		}
		e.source(c, role, val)
	}
}

func sortedInputNames(inputs inputSet) []string {
	names := make([]string, 0, len(inputs.kinds))
	for name := range inputs.kinds {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
