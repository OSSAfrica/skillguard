package extract

import (
	"net/url"
	"strings"

	"skillguard/internal/model"
)

// Only explicitly known switches are consumed. Unknown flags leave a coverage
// gap instead of silently guessing which following argument is a package.
var booleanFlags = map[string]bool{
	"--global": true, "-g": true, "--save": true, "--save-dev": true, "-D": true, "-S": true,
	"--save-exact": true, "-E": true, "--ignore-scripts": true, "--no-audit": true,
	"--no-fund": true, "--yes": true, "-y": true, "--no": true,
	"--user": true, "--upgrade": true, "-U": true, "--no-deps": true,
	"--no-cache-dir": true, "--pre": true, "--require-hashes": true,
	"--isolated": true, "--no-index": true, "--no-input": true,
}

var valueFlags = map[string]string{
	"--registry": "registry", "--index-url": "index", "-i": "index", "--extra-index-url": "extra_index",
	"--find-links": "find_links", "-f": "find_links", "--trusted-host": "trusted_host",
	"--requirement": "requirements", "-r": "requirements", "--constraint": "constraints", "-c": "constraints",
	"--userconfig": "config", "--config": "config", "--prefix": "context", "--target": "context", "-t": "context",
	"--workspace": "context", "-w": "context", "--omit": "selection", "--include": "selection",
	"--only-binary": "selection", "--no-binary": "selection", "--python": "context",
	"--cache": "context", "--timeout": "selection", "--retries": "selection",
	"--editable": "dependency", "-e": "dependency",
}

func (e *extractor) packages(command *model.DocumentCommand, args []string) {
	ecosystem := "pypi"
	if command.Tool == "npm" || command.Tool == "npx" {
		ecosystem = "npm"
	}
	explicitPackage := false
	positional := false
	options := true
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if command.Operation == "exec" && positional && (command.Tool != "npm" || !options) {
			// These are arguments to the invoked program, not package specs.
			break
		}
		if command.Operation == "exec" && positional && !strings.HasPrefix(arg, "-") {
			e.gap("exec_arguments_unresolved", "Use an explicit -- delimiter to distinguish npm exec program arguments from manager options.", command.Location)
			return
		}
		if options && arg == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(arg, "-") {
			consumed, explicit, ok := e.packageOption(command, ecosystem, args[i:])
			if !ok {
				return
			}
			i += consumed - 1
			explicitPackage = explicitPackage || explicit
			continue
		}
		positional = true
		if command.Operation != "exec" || !explicitPackage {
			e.addDependency(command, ecosystem, arg)
		}
	}
	if command.Tool == "npm" && (command.Operation == "ci" || (command.Operation == "install" && len(command.Dependencies) == 0)) {
		e.input(command, "package.json", "manifest")
		e.input(command, "package-lock.json", "lockfile")
		// No resolution is performed in this phase. The references must never
		// be mistaken for an empty dependency set or a verified lockfile.
		e.gap("dependency_resolution_required", "Manifest/lockfile dependencies require a separate resolution assessment.", command.Location)
	}
	if command.Operation == "exec" && len(command.Dependencies) == 0 {
		e.gap("execution_target_unresolved", "The package supplying the executable could not be identified.", command.Location)
	}
	if (command.Tool == "pip" || command.Tool == "pip3") && len(command.Dependencies) == 0 && len(command.Inputs) == 0 {
		e.gap("missing_dependency", "No dependency or requirements input was identified.", command.Location)
	}
}

func (e *extractor) packageOption(command *model.DocumentCommand, ecosystem string, args []string) (consumed int, explicit, ok bool) {
	arg := args[0]
	flag, value, hasValue := strings.Cut(arg, "=")
	if !hasValue && len(arg) > 2 && (strings.HasPrefix(arg, "-r") || strings.HasPrefix(arg, "-c") || strings.HasPrefix(arg, "-i")) && ecosystem == "pypi" {
		flag, value, hasValue = arg[:2], arg[2:], true
	}
	if booleanFlags[flag] && !hasValue {
		if !flagForEcosystem(ecosystem, flag) {
			e.gap("unsupported_option", "An option does not belong to the supported ecosystem subset.", command.Location)
			return 0, false, false
		}
		command.Options = append(command.Options, model.CommandOption{Name: flag})
		return 1, false, true
	}
	role := valueFlags[flag]
	if !flagForEcosystem(ecosystem, flag) {
		role = ""
	}
	if command.Operation == "exec" && ((ecosystem == "npm" && (flag == "--package" || flag == "-p")) || (flag == "--from" && command.Tool == "uvx") || (flag == "--spec" && command.Tool == "pipx")) {
		role, explicit = "dependency", true
	}
	if role == "" {
		e.gap("unsupported_option", "An unknown option prevents complete argument interpretation.", command.Location)
		return 0, false, false
	}
	consumed = 1
	if !hasValue {
		if len(args) < 2 || strings.HasPrefix(args[1], "-") {
			e.gap("missing_option_value", "A required option value is absent or ambiguous.", command.Location)
			return 0, false, false
		}
		consumed, value = 2, args[1]
	}
	e.option(command, ecosystem, role, value)
	if role == "selection" && command.Context == "action" && ecosystem == "pypi" && flag == "--only-binary" && value == ":all:" {
		command.Options = append(command.Options, model.CommandOption{Name: flag, Value: value})
		return consumed, explicit, true
	}
	if role == "selection" {
		// Selection arguments can contain arbitrary input; preserve the switch
		// but do not echo an unchecked value into the evidence channel.
		command.Options = append(command.Options, model.CommandOption{Name: flag})
		e.gap("selection_unresolved", "A dependency-selection option requires package-manager-specific resolution.", command.Location)
	}
	return consumed, explicit, true
}

// Shared spellings are interpreted only for their documented ecosystem.
func flagForEcosystem(ecosystem, flag string) bool {
	if ecosystem == "npm" {
		switch flag {
		case "--global", "-g", "--save", "--save-dev", "-D", "-S", "--save-exact", "-E", "--ignore-scripts", "--no-audit", "--no-fund", "--yes", "-y", "--no", "--registry", "--userconfig", "--prefix", "--workspace", "-w", "--omit", "--include":
			return true
		}
		return false
	}
	switch flag {
	case "--global", "-g", "--save", "--save-dev", "-D", "-S", "--save-exact", "-E", "--ignore-scripts", "--no-audit", "--no-fund", "--yes", "-y", "--no", "--registry", "--userconfig", "--workspace", "-w", "--omit", "--include":
		return false
	}
	return true
}

func (e *extractor) option(command *model.DocumentCommand, ecosystem, role, value string) {
	switch role {
	case "registry", "index", "extra_index", "find_links":
		e.destination(command, value, role)
	case "trusted_host":
		e.gap("trust_override", "The command overrides transport trust; this does not establish package identity.", command.Location)
	case "requirements", "constraints", "manifest", "lockfile", "config":
		e.input(command, value, role)
	case "context":
		e.gap("execution_context_unresolved", "An option changes working directory, interpreter, or installation context.", command.Location)
	case "dependency":
		e.addDependency(command, ecosystem, value)
	}
}

func (e *extractor) addDependency(command *model.DocumentCommand, ecosystem, spec string) {
	d, ok := dependency(ecosystem, spec)
	if !ok {
		e.gap("unresolved_package_spec", "A package specification is outside the supported static grammar.", command.Location)
	}
	command.Dependencies = append(command.Dependencies, d)
	if d.Source == "url" || d.Source == "git" {
		if strings.Contains(d.Specifier, "://") {
			e.destination(command, d.Specifier, "dependency")
		}
	}
	if d.Source == "local" {
		e.gap("local_dependency_unresolved", "Local dependency contents are not resolved by command extraction.", command.Location)
	}
}

func (e *extractor) destination(command *model.DocumentCommand, value, role string) {
	if command.Context == "action" && value != SafeSource(value) {
		e.gap("destination_redacted", "An action source contains URL components that cannot be resolved from redacted evidence.", command.Location)
	}
	u, err := url.Parse(value)
	if err != nil || u.Hostname() == "" || (u.Scheme != "https" && u.Scheme != "http" && u.Scheme != "git+https" && u.Scheme != "git+http" && u.Scheme != "ssh" && u.Scheme != "git+ssh") {
		e.gap("unresolved_destination", "A destination is not a supported absolute URL.", command.Location)
		return
	}
	command.Destinations = append(command.Destinations, model.Destination{URL: SafeSource(value), Role: role})
}

func (e *extractor) download(command *model.DocumentCommand, args []string) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://") {
			e.destination(command, arg, "download")
			continue
		}
		flag, value, hasValue := strings.Cut(arg, "=")
		if flag == "-O" && command.Tool == "curl" {
			continue
		}
		if flag == "--url" {
			if !hasValue && i+1 < len(args) {
				i++
				value, hasValue = args[i], true
			}
			if hasValue {
				e.destination(command, value, "download")
				continue
			}
		}
		// Transport flags and output paths are not copied into evidence.
		if downloadValueFlags[flag] {
			if !hasValue && i+1 < len(args) {
				i++
			}
			continue
		}
		if downloadBooleanFlags[arg] {
			continue
		}
		e.gap("unsupported_option", "A download option or argument could not be interpreted completely.", command.Location)
	}
	if len(command.Destinations) == 0 {
		e.gap("unresolved_destination", "No literal download destination was identified.", command.Location)
	}
	// Fetching and following downloaded scripts is intentionally outside this
	// phase. Existing security detectors still flag piped installers.
	e.gap("download_contents_unscanned", "Downloaded content is not fetched or executed; a destination is not an artifact safety verdict.", command.Location)
}

var downloadValueFlags = map[string]bool{
	"-o": true, "-O": true, "--output": true, "--output-document": true,
	"-H": true, "--header": true, "-u": true, "--user": true,
}

var downloadBooleanFlags = map[string]bool{
	"-fsSL": true, "-fsS": true, "-sSL": true, "-s": true, "-q": true,
	"-L": true, "-f": true, "--silent": true, "--fail": true, "--location": true,
	"-qO-": true, "-O-": true,
}
