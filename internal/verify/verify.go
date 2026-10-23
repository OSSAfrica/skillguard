package verify

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"time"

	"skillguard/internal/model"
)

type IntelligenceObservation struct {
	KnownMalicious bool
	SourceID       string
}

// Intelligence is an optional operator-provided extension. No feed is installed
// or contacted by default; a negative match never establishes legitimacy.
type Intelligence interface {
	Check(context.Context, string, string, string) (IntelligenceObservation, error)
}

type Options struct {
	Resolver     Resolver
	TLSConfig    *tls.Config
	Now          func() time.Time
	Wait         func(context.Context, time.Duration) error
	Intelligence Intelligence
}

type cacheEntry struct {
	observation model.PackageObservation
	expires     time.Time
}

type Verifier struct {
	policy       Policy
	now          func() time.Time
	wait         func(context.Context, time.Duration) error
	intelligence Intelligence
	broker       *broker
	cache        map[string]cacheEntry
	serial       chan struct{}
	requests     int
	nextRequest  time.Time
}

func New(policy Policy, options Options) (*Verifier, error) {
	// Keep operator configuration immutable even if the caller reuses slices.
	policy.Registries = append([]Registry(nil), policy.Registries...)
	policy.DNSHosts = append([]string(nil), policy.DNSHosts...)
	for i := range policy.Registries {
		policy.Registries[i].Packages = append([]string(nil), policy.Registries[i].Packages...)
	}
	if err := policy.validate(); err != nil {
		return nil, err
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Wait == nil {
		options.Wait = waitContext
	}
	if options.Resolver == nil {
		options.Resolver = net.DefaultResolver
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	if options.TLSConfig != nil {
		config = options.TLSConfig.Clone()
	}
	if config.InsecureSkipVerify {
		return nil, errors.New("verification requires TLS certificate validation")
	}
	if config.MinVersion < tls.VersionTLS12 {
		config.MinVersion = tls.VersionTLS12
	}
	v := &Verifier{policy: policy, now: options.Now, wait: options.Wait, intelligence: options.Intelligence, cache: map[string]cacheEntry{}, serial: make(chan struct{}, 1)}
	v.broker = &broker{resolver: options.Resolver, connect: (&net.Dialer{Timeout: time.Duration(policy.TimeoutSeconds) * time.Second}).DialContext, tlsConfig: config, owner: v, clients: map[string]*http.Client{}}
	return v, nil
}

func (v *Verifier) Close() {
	v.serial <- struct{}{}
	defer func() { <-v.serial }()
	for _, c := range v.broker.clients {
		c.CloseIdleConnections()
	}
}

func waitContext(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (v *Verifier) reserve(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if v.requests >= v.policy.MaxRequests {
		return errBudget
	}
	now := v.now()
	delay := v.nextRequest.Sub(now)
	if delay < 0 {
		delay = 0
	}
	v.requests++
	v.nextRequest = now.Add(delay + time.Duration(v.policy.MinIntervalMS)*time.Millisecond)
	return v.wait(ctx, delay)
}

func newResult() *model.ReferenceVerification {
	return &model.ReferenceVerification{Status: "complete", Packages: []model.PackageObservation{}, Destinations: []model.DestinationObservation{}, Gaps: []model.CoverageGap{}}
}

func (v *Verifier) Verify(ctx context.Context, extraction *model.Extraction) *model.ReferenceVerification {
	result := newResult()
	select {
	case v.serial <- struct{}{}:
		defer func() { <-v.serial }()
	case <-ctx.Done():
		result.Status = "partial"
		result.Gaps = append(result.Gaps, model.CoverageGap{Code: "verification_canceled", Message: "Verification was canceled before starting."})
		return result
	}
	if extraction == nil || extraction.Status != "complete" {
		result.Status = "partial"
		result.Gaps = append(result.Gaps, model.CoverageGap{Code: "extraction_incomplete", Message: "Verification cannot cover commands or inputs that extraction did not resolve."})
	}
	if extraction == nil {
		return result
	}
	for _, command := range extraction.Commands {
		for _, dep := range command.Dependencies {
			if observationLimit(result) {
				return result
			}
			observations := v.dependency(ctx, command, dep, extraction.Gaps)
			for _, observation := range observations {
				if observationLimit(result) {
					return result
				}
				v.signals(&observation)
				if !observationComplete(observation) {
					result.Status = "partial"
				}
				result.Packages = append(result.Packages, observation)
			}
		}
		for _, destination := range command.Destinations {
			if observationLimit(result) {
				return result
			}
			observation := v.destination(ctx, destination, command.Location)
			if observation.Resolution != "resolved" && observation.Resolution != "literal" && observation.Resolution != "not_requested" && observation.Resolution != "not_found" {
				result.Status = "partial"
			}
			result.Destinations = append(result.Destinations, observation)
		}
	}
	return result
}

func observationLimit(result *model.ReferenceVerification) bool {
	if len(result.Packages)+len(result.Destinations) < 512 {
		return false
	}
	result.Status = "partial"
	result.Gaps = append(result.Gaps, model.CoverageGap{Code: "verification_limit", Message: "Further verification stopped at the 512-observation limit."})
	return true
}

func observationComplete(p model.PackageObservation) bool {
	return (p.State == "found" || p.State == "missing") && p.VersionState != "unsupported_specifier" && p.MalwareCheck != "unavailable"
}

func (v *Verifier) blank(dep model.Dependency, location model.SourceSpan) model.PackageObservation {
	return model.PackageObservation{Ecosystem: dep.Ecosystem, Name: dep.Name, RequestedSpecifier: dep.Specifier, SourceSelection: "unresolved", State: "unsupported_source", VersionState: "unknown", Identity: "unverified", Provenance: "not_checked", MalwareCheck: "not_performed", ObservedAt: v.now().UTC(), Location: location}
}

func (v *Verifier) dependency(ctx context.Context, command model.DocumentCommand, dep model.Dependency, gaps []model.CoverageGap) []model.PackageObservation {
	base := v.blank(dep, command.Location)
	name, ok := normalizeName(dep.Ecosystem, dep.Name)
	if !ok || dep.Source != "registry" || len(dep.Specifier) > 1024 {
		base.Name = "[unresolved dependency]"
		base.RequestedSpecifier = ""
		base.Reason = "unsupported_dependency_source"
		return []model.PackageObservation{base}
	}
	base.Name = name
	if sourceUnresolved(command, gaps) {
		base.State, base.Reason = "blocked", "effective_source_unresolved"
		return []model.PackageObservation{base}
	}
	routes, selection, ok := v.routes(command, dep.Ecosystem)
	base.SourceSelection = selection
	if !ok || len(routes) == 0 {
		base.Reason = "registry_not_authorized"
		return []model.PackageObservation{base}
	}
	result := make([]model.PackageObservation, 0, len(routes))
	for _, registry := range routes {
		observation := base
		observation.Registry = registry.ID
		if !allowedPackage(registry, name) {
			observation.State, observation.Reason = "blocked", "package_disclosure_not_authorized"
		} else {
			observation = v.lookup(ctx, registry, observation)
		}
		result = append(result, observation)
	}
	return result
}

func sourceUnresolved(command model.DocumentCommand, gaps []model.CoverageGap) bool {
	for _, option := range command.Options {
		if option.Name == "--no-index" || option.Name == "--isolated" {
			return true
		}
	}
	for _, input := range command.Inputs {
		if input.Kind == "config" || input.Kind == "requirements" || input.Kind == "constraints" {
			return true
		}
	}
	for _, destination := range command.Destinations {
		if destination.Role == "find_links" {
			return true
		}
	}
	for _, gap := range gaps {
		// These constructs can change sources for later commands. Without a
		// resolved execution context, a line-local match is insufficient.
		switch gap.Code {
		case "environment_unresolved", "execution_context_unresolved", "control_flow":
			return true
		}
		if gap.Location.Source != command.Location.Source || gap.Location.EndLine < command.Location.StartLine || gap.Location.StartLine > command.Location.EndLine {
			continue
		}
		switch gap.Code {
		case "environment_unresolved", "wrapper_unresolved", "execution_context_unresolved", "unresolved_destination", "unsupported_option":
			return true
		}
	}
	return false
}

func (v *Verifier) routes(command model.DocumentCommand, ecosystem string) ([]Registry, string, bool) {
	var explicit []string
	primary := false
	for _, d := range command.Destinations {
		if (ecosystem == "npm" && d.Role == "registry") || (ecosystem == "pypi" && d.Role == "index") {
			if primary {
				return nil, "explicit", false
			}
			primary = true
			explicit = append(explicit, d.URL)
		}
		if ecosystem == "pypi" && d.Role == "extra_index" {
			explicit = append(explicit, d.URL)
		}
	}
	var routes []Registry
	if !primary {
		for _, r := range v.policy.Registries {
			if r.Ecosystem == ecosystem && r.Default {
				routes = append(routes, r)
			}
		}
		if len(routes) == 0 {
			return nil, "policy_default", false
		}
	}
	for _, endpoint := range explicit {
		canonical, ok := canonicalEndpoint(endpoint)
		if !ok {
			return nil, "explicit", false
		}
		matched := false
		for _, r := range v.policy.Registries {
			if r.Ecosystem == ecosystem && r.InstallURL == canonical {
				routes = append(routes, r)
				matched = true
				break
			}
		}
		if !matched {
			return nil, "explicit", false
		}
	}
	selection := "policy_default"
	if len(explicit) > 0 {
		selection = "explicit"
	}
	return routes, selection, true
}

func (v *Verifier) lookup(ctx context.Context, r Registry, base model.PackageObservation) model.PackageObservation {
	key := r.ID + "\x00" + base.Name + "\x00" + base.RequestedSpecifier
	if err := ctx.Err(); err != nil {
		base.State = errorState(err)
		return base
	}
	entry, hadEntry := v.cache[key]
	if hadEntry && v.now().Before(entry.expires) {
		cached := entry.observation
		cached.FromCache = true
		cached.Location = base.Location
		cached.SourceSelection = base.SourceSelection
		return cached
	}
	delete(v.cache, key)
	var adapter RegistryClient = NPMClient{}
	if r.Ecosystem == "pypi" {
		adapter = PyPIClient{}
	}
	base.MetadataURL = r.MetadataURL + adapter.MetadataPath(base.Name)
	ctx, cancel := context.WithTimeout(ctx, time.Duration(v.policy.TimeoutSeconds)*time.Second)
	defer cancel()
	body, state, reason := v.broker.Fetch(ctx, r, base.MetadataURL)
	base.State, base.Reason = state, reason
	if state == "found" {
		applyMetadata(&base, adapter.Inspect(body, base.Name, base.RequestedSpecifier))
	}
	base.ObservedAt = v.now().UTC()
	if base.State == "found" && v.intelligence != nil {
		intel, err := v.intelligence.Check(ctx, base.Ecosystem, base.Name, base.Version)
		switch {
		case err != nil:
			base.MalwareCheck = "unavailable"
		case intel.KnownMalicious:
			base.MalwareCheck = "matched"
		default:
			base.MalwareCheck = "no_known_match"
		}
		if identifier.MatchString(intel.SourceID) {
			base.IntelligenceSource = intel.SourceID
		}
	}
	if (base.State == "found" || base.State == "missing") && base.MalwareCheck != "unavailable" {
		ttl := time.Duration(v.policy.CacheTTLSeconds) * time.Second
		if (base.State == "missing" || base.VersionState == "missing") && ttl > time.Minute {
			ttl = time.Minute
		}
		expires := base.ObservedAt.Add(ttl)
		base.ExpiresAt = &expires
		v.cache[key] = cacheEntry{observation: base, expires: expires}
	} else {
		base.StaleEvidenceDiscarded = hadEntry
	}
	return base
}

func applyMetadata(base *model.PackageObservation, m Metadata) {
	base.State, base.Reason, base.VersionState = m.State, m.Reason, m.VersionState
	base.Version, base.PublishedAt, base.ClaimedRepositoryURL, base.Provenance = m.Version, m.PublishedAt, m.Repository, m.Provenance
}

func (v *Verifier) signals(p *model.PackageObservation) {
	p.Signals = nil
	add := func(id, message, next string) {
		p.Signals = append(p.Signals, model.VerificationSignal{ID: id, Message: message, NextStep: next})
	}
	if p.State == "missing" {
		add("SG_PACKAGE_MISSING", "Package was not found at the configured metadata endpoint; this is not proof of malware.", "Confirm the intended package and registry with the project maintainer.")
	}
	if p.VersionState == "missing" {
		add("SG_VERSION_MISSING", "Requested version or tag was not found in registry metadata.", "Confirm a reviewed version at the intended registry.")
	}
	if p.RequestedSpecifier == "" || p.VersionState == "not_requested" {
		add("SG_VERSION_UNPINNED", "The command does not identify a fixed reviewed version.", "Use a reviewed version or lockfile; pinning alone does not establish legitimacy.")
	}
	if p.Ecosystem == "npm" && npmTag.MatchString(p.RequestedSpecifier) {
		add("SG_MUTABLE_VERSION_TAG", "A registry tag can select a different version later.", "Review and bind the intended artifact before execution.")
	}
	if p.State == "found" {
		add("SG_IDENTITY_UNVERIFIED", "Registry existence and publisher-provided metadata do not establish project identity or package safety.", "Confirm the relationship through independent project evidence before trusting the artifact.")
	}
	if p.PublishedAt != nil && !p.PublishedAt.After(v.now()) && v.now().Sub(*p.PublishedAt) < 30*24*time.Hour {
		add("SG_RECENT_PUBLICATION", "The observed version was published within 30 days; recency is a review signal, not a malware verdict.", "Review the publisher and artifact history.")
	}
	if p.MalwareCheck == "matched" {
		add("SG_MALWARE_INTELLIGENCE_MATCH", "The configured intelligence provider reported a known malicious match.", "Do not execute the artifact; investigate the attributed intelligence result.")
	}
	if !observationComplete(*p) {
		add("SG_VERIFICATION_INCOMPLETE", "A required metadata observation could not be completed.", "Resolve the reported source, policy, or lookup failure; do not interpret this as a clean check.")
	}
}
