package assess

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
	"time"

	"skillguard/internal/extract"
	"skillguard/internal/model"
	"skillguard/internal/verify"
)

type ReferenceVerifier interface {
	Verify(context.Context, *model.Extraction) *model.ReferenceVerification
}
type Options struct {
	EngineVersion string
	Now           func() time.Time
	Verifier      ReferenceVerifier
}
type evaluation struct {
	request  Request
	policy   Policy
	response Response
	mutable  bool
}

func bytesHash(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Evaluate accepts validated request/policy values but revalidates them so library
// callers cannot bypass CLI schema checks. Optional injected verification is a
// trusted embedding interface, never an agent-supplied observation.
func Evaluate(ctx context.Context, request Request, policy Policy, options Options) Response {
	clock := options.Now
	if clock == nil {
		clock = time.Now
	}
	now := clock()
	encodedRequest, _ := marshal(request)
	if _, err := DecodeRequest(encodedRequest); err != nil || policy.validate() != nil {
		return ErrorResponse(options.EngineVersion, "SG_REQUEST_POLICY_INVALID", now)
	}
	e := &evaluation{request: request, policy: policy, response: newResponse(options.EngineVersion, now)}
	r := &e.response
	r.Status = "complete"
	r.Decision = "allow"
	r.PolicyIdentity = policy.ID
	r.PolicyVersion = policy.Version
	r.PolicyFingerprint = fingerprint(policy)
	r.SubjectFingerprint = fingerprint(request.Action)
	r.ExpiresAt = now.UTC().Add(time.Duration(policy.MaxAgeSeconds) * time.Second)
	realRoot, rootErr := filepath.EvalSymlinks(request.TargetRoot)
	realCWD, cwdErr := filepath.EvalSymlinks(request.CWD)
	if rootErr != nil || cwdErr != nil {
		return ErrorResponse(options.EngineVersion, "SG_INPUT_BOUNDARY", now)
	}
	relative, err := filepath.Rel(realRoot, realCWD)
	if err != nil || (relative != "." && !filepath.IsLocal(relative)) {
		return ErrorResponse(options.EngineVersion, "SG_INPUT_BOUNDARY", now)
	}
	inputs := e.readInputs()
	r.ContextFingerprint = fingerprint(struct {
		TargetRoot  string
		CWD         string
		RealRoot    string
		RealCWD     string
		Environment map[string]string
		Profile     string
		Inputs      []InputFact
	}{request.TargetRoot, request.CWD, realRoot, realCWD, request.Environment, request.ContextProfile, r.Inputs})
	e.executionContext()
	x := extract.Action(request.Action.Argv, request.Action.Command)
	// Input readability and resolution are handled against the explicit boundary,
	// instead of documentation's parent-directory heuristic.
	resolved := map[string]bool{"input_base_unavailable": true, "dependency_input_unresolved": true, "dependency_resolution_required": true}
	gaps := make([]model.CoverageGap, 0, len(x.Gaps))
	for _, g := range x.Gaps {
		if !resolved[g.Code] {
			gaps = append(gaps, g)
			e.gap("SG_ACTION_UNSUPPORTED", "The exact action contains unsupported syntax, context, options, or inputs.")
		}
	}
	x.Gaps = gaps
	x.Status = "complete"
	if len(gaps) > 0 {
		x.Status = "partial"
	}
	for i := range x.Commands {
		c := &x.Commands[i]
		if c.PipedToExecution {
			e.deny("SG_REMOTE_EXECUTION", "A downloaded payload is piped to an interpreter.")
		}
		if c.Operation == "download" {
			e.deny("SG_REMOTE_EXECUTION", "Remote download actions cannot be authorized by this install-only ruleset.")
		}
		e.sources(c) // Require an explicit source on the actual command before config resolution.
		e.resolve(c, inputs)
		e.sources(c)
	}
	if len(x.Commands) != 1 {
		e.gap("SG_ACTION_CARDINALITY", "Exactly one supported install command is required.")
	}
	r.Checks = append(r.Checks, Check{ID: "static_action_inputs", Required: true, Status: r.Status})
	e.metadata(ctx, x, options.Verifier)
	if ctx.Err() != nil {
		e.gap("SG_ASSESSMENT_CANCELED", "Assessment was canceled.")
	}
	e.baseline(now)
	if r.Status != "complete" && r.Decision == "allow" {
		r.Decision = "review"
	}
	r.EvidenceFingerprint = fingerprint(struct {
		Dependencies []DependencyFact
		Verification *model.ReferenceVerification
	}{r.Dependencies, r.Verification})
	if r.Verification != nil {
		for _, p := range r.Verification.Packages {
			if p.ExpiresAt != nil && p.ExpiresAt.Before(r.ExpiresAt) {
				r.ExpiresAt = *p.ExpiresAt
			}
		}
	}
	if !clock().Before(r.ExpiresAt) {
		e.gap("SG_ASSESSMENT_EXPIRED", "The assessment exceeded its evidence or policy lifetime; reassess.")
	}
	if r.Status != "complete" {
		r.ExpiresAt = r.AssessedAt
	}
	r.DecisionFingerprint = fingerprint(*r)
	return *r
}

func (e *evaluation) rule(id, effect, message string) {
	for _, r := range e.response.Rules {
		if r.ID == id {
			return
		}
	}
	next := "Resolve the reported coverage gap and reassess."
	if effect == "review" {
		next = "Have an operator independently review this exact action and context; update the protected policy and reassess."
	}
	if effect == "deny" {
		next = "Remove the prohibited action or dependency and reassess."
	}
	e.response.Rules = append(e.response.Rules, Rule{ID: id, Effect: effect, Message: message, Remediation: next, Location: model.SourceSpan{Source: "action", StartLine: 1, EndLine: 1}})
}
func (e *evaluation) gap(id, message string) {
	e.response.Status = "partial"
	e.rule(id, "incomplete", message)
	if e.response.Decision != "deny" {
		e.response.Decision = "review"
	}
}
func (e *evaluation) deny(id, message string) {
	e.response.Decision = "deny"
	e.rule(id, "deny", message)
}
func (e *evaluation) review(id, message string) {
	if e.response.Decision != "deny" {
		e.response.Decision = "review"
	}
	e.rule(id, "review", message)
}

func (e *evaluation) executionContext() {
	matched := false
	for _, id := range e.policy.IsolatedProfiles {
		if id == e.request.ContextProfile {
			matched = true
		}
	}
	if !matched {
		e.gap("SG_CONTEXT_UNVERIFIED", "No operator-approved isolated execution profile matches this request.")
	}
	// A profile cannot override source-changing environment without a resolver.
	for name := range e.request.Environment {
		upper := strings.ToUpper(name)
		if strings.HasPrefix(upper, "PIP_") || strings.HasPrefix(upper, "NPM_CONFIG_") || strings.HasPrefix(upper, "UV_") || strings.HasPrefix(upper, "PYTHON") || strings.HasPrefix(upper, "NODE_") || strings.HasPrefix(upper, "LD_") || strings.HasPrefix(upper, "DYLD_") || upper == "BASH_ENV" || upper == "ENV" || upper == "SHELLOPTS" {
			e.gap("SG_ENVIRONMENT_UNRESOLVED", "The environment contains unresolved source or interpreter configuration.")
		}
	}
}

func (e *evaluation) source(c *model.DocumentCommand, role, raw string) {
	// Never authorize a redacted URL: credentials/query/fragment must not make two
	// different effective sources appear equivalent after display sanitization.
	if raw != extract.SafeSource(raw) {
		e.deny("SG_SOURCE_PROHIBITED", "Source URL contains unsupported hidden or credential-bearing components.")
		return
	}
	for _, d := range c.Destinations {
		if d.Role == role && d.URL == raw {
			return
		}
	}
	c.Destinations = append(c.Destinations, model.Destination{Role: role, URL: raw})
}

func (e *evaluation) sources(c *model.DocumentCommand) {
	eco, primary := "pypi", "index"
	if c.Tool == "npm" {
		eco, primary = "npm", "registry"
	}
	count := 0
	for _, d := range c.Destinations {
		if d.Role != primary {
			e.deny("SG_SOURCE_PROHIBITED", "Multiple indexes, find-links and direct artifact sources are prohibited.")
			continue
		}
		count++
		matched := false
		if e.policy.Verification != nil {
			for _, r := range e.policy.Verification.Registries {
				if r.Ecosystem == eco && strings.TrimRight(r.InstallURL, "/") == strings.TrimRight(d.URL, "/") {
					matched = true
				}
			}
		}
		if !matched {
			e.deny("SG_SOURCE_PROHIBITED", "The effective registry is not explicitly configured by the operator.")
		}
	}
	if count != 1 {
		e.gap("SG_SOURCE_UNRESOLVED", "One explicit effective registry/index is required; package-manager defaults are not inferred.")
	}
}

func (e *evaluation) metadata(ctx context.Context, x *model.Extraction, v ReferenceVerifier) {
	check := Check{ID: "registry_metadata", Required: e.policy.RequireMetadata, Status: "not_requested"}
	if !e.policy.RequireMetadata {
		e.response.Checks = append(e.response.Checks, check)
		return
	}
	if e.response.Status != "complete" || e.response.Decision == "deny" {
		check.Status = "partial"
		e.gap("SG_METADATA_INCOMPLETE", "Required metadata checks were withheld because static context or policy checks failed.")
		e.response.Checks = append(e.response.Checks, check)
		return
	}
	if v == nil {
		configured, err := verify.New(*e.policy.Verification, verify.Options{})
		if err != nil {
			check.Status = "error"
			e.gap("SG_METADATA_INCOMPLETE", "The required metadata verifier could not be initialized.")
			e.response.Checks = append(e.response.Checks, check)
			return
		}
		defer configured.Close()
		v = configured
	}
	// Static input/source handling above resolved these options; the generic
	// documentation verifier intentionally does not assume that resolution.
	for i := range x.Commands {
		var options []model.CommandOption
		for _, o := range x.Commands[i].Options {
			if o.Name != "--isolated" {
				options = append(options, o)
			}
		}
		x.Commands[i].Options = options
	}
	result := v.Verify(ctx, x)
	e.response.Verification = result
	check.Status = "complete"
	if result == nil || result.Status != "complete" {
		check.Status = "partial"
		e.gap("SG_METADATA_INCOMPLETE", "Required registry metadata checks did not complete.")
	}
	if result != nil {
		if len(result.Packages) != len(e.response.Dependencies) {
			check.Status = "partial"
			e.gap("SG_METADATA_INCOMPLETE", "Metadata coverage does not match the resolved dependency set.")
		}
		for _, p := range result.Packages {
			if p.State == "found" && (p.ExpiresAt == nil || !p.ExpiresAt.After(e.response.AssessedAt) || p.ObservedAt.After(e.response.AssessedAt.Add(time.Minute))) {
				check.Status = "partial"
				e.gap("SG_METADATA_STALE", "Required metadata has no current bounded evidence lifetime.")
			}
			if p.State == "missing" || p.VersionState == "missing" {
				e.deny("SG_REFERENCE_MISSING", "A required package or version is missing at the configured registry.")
			}
			if p.MalwareCheck == "matched" {
				e.deny("SG_MALWARE_CONFIRMED", "The trusted intelligence provider reported a malicious artifact.")
			}
			if p.State != "found" && p.State != "missing" || p.State == "found" && p.VersionState != "found" {
				check.Status = "partial"
				e.gap("SG_METADATA_INCOMPLETE", "A required exact-version metadata check did not complete.")
			}
		}
	}
	e.response.Checks = append(e.response.Checks, check)
}

func (e *evaluation) baseline(now time.Time) {
	r := &e.response
	var match *Baseline
	for i := range e.policy.ReviewedActions {
		b := &e.policy.ReviewedActions[i]
		if b.SubjectFingerprint == r.SubjectFingerprint && b.ContextFingerprint == r.ContextFingerprint && now.Before(b.ExpiresAt) {
			match = b
			break
		}
	}
	if match == nil {
		e.review("SG_REVIEW_REQUIRED", "This exact action and input context do not have a current operator review.")
		return
	}
	r.ReviewID = match.ReviewID
	if match.ExpiresAt.Before(r.ExpiresAt) {
		r.ExpiresAt = match.ExpiresAt
	}
	if e.mutable && !match.AcceptMutableArtifacts {
		e.review("SG_ARTIFACT_UNBOUND", "An artifact is not cryptographically bound by enforced input hashes.")
	}
	if e.mutable {
		e.rule("SG_MUTABLE_ARTIFACT_LIMIT", "info", "Version/source review does not bind the bytes returned by a mutable registry; the baseline must explicitly accept this limit.")
	}
	// No baseline can erase an earlier deny/review/partial result.
	r.Checks = append(r.Checks, Check{ID: "operator_review", Required: true, Status: "complete"})
}
