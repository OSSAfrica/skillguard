package cmd

import (
	"errors"
	"fmt"
	"strings"

	"skillguard/internal/model"
	"skillguard/internal/verify"
)

var verifyReferences bool
var verificationPolicy string
var errReferencesFailed = errors.New("one or more reference checks failed")
var errVerificationIncomplete = errors.New("reference verification incomplete; inspect verification observations")

func configuredVerifier() (*verify.Verifier, error) {
	if !verifyReferences {
		if verificationPolicy != "" {
			return nil, errors.New("--verification-policy requires --verify-references")
		}
		return nil, nil
	}
	if verificationPolicy == "" {
		return nil, errors.New("--verify-references requires an explicitly selected --verification-policy")
	}
	policy, err := verify.LoadPolicy(verificationPolicy)
	if err != nil {
		return nil, err
	}
	return verify.New(policy, verify.Options{})
}

func verificationOutcome(report *model.ScanReport) error {
	missing := false
	for _, result := range report.Results {
		if result.Verification == nil {
			continue
		}
		if result.Verification.Status != "complete" {
			return errVerificationIncomplete
		}
		for _, p := range result.Verification.Packages {
			missing = missing || p.State == "missing" || p.VersionState == "missing" || p.MalwareCheck == "matched"
		}
	}
	if missing {
		return errReferencesFailed
	}
	return nil
}

func printVerification(result *model.AnalysisResult, details bool) {
	if result.Verification == nil {
		return
	}
	v := result.Verification
	fmt.Printf("  Reference verification: %s; %d package observations, %d destinations. Identity remains unverified.\n", v.Status, len(v.Packages), len(v.Destinations))
	for _, p := range v.Packages {
		if !details && p.State == "found" && p.VersionState != "missing" && p.VersionState != "unsupported_specifier" && p.MalwareCheck != "matched" {
			continue
		}
		fmt.Printf("    %q/%q at %q: %s; requested version: %s\n", p.Ecosystem, p.Name, p.Registry, p.State, p.VersionState)
		for _, s := range p.Signals {
			fmt.Printf("      %s: %s %s\n", s.ID, s.Message, s.NextStep)
		}
	}
	if details {
		for _, d := range v.Destinations {
			fmt.Printf("    Destination %q: DNS %s, scope %s; ownership %s, reachability %s\n", d.Host, d.Resolution, d.AddressScope, d.Ownership, d.Reachability)
		}
	}
	for _, gap := range v.Gaps {
		fmt.Printf("    Verification coverage: %s — %s\n", gap.Code, gap.Message)
	}
}

func verificationMarkdown(report *model.ScanReport) string {
	var out strings.Builder
	for _, r := range report.Results {
		if r.Verification == nil {
			continue
		}
		fmt.Fprintf(&out, "\n## Reference metadata: %s\n\nStatus: %s. Existence does not establish identity or authorize execution.\n\n", markdownText(r.FilePath), r.Verification.Status)
		for _, p := range r.Verification.Packages {
			fmt.Fprintf(&out, "- %s **%s** at %s: %s; version %s (%s); identity %s; malware check %s\n", p.Ecosystem, markdownText(p.Name), markdownText(p.Registry), p.State, markdownText(p.Version), p.VersionState, p.Identity, p.MalwareCheck)
			for _, s := range p.Signals {
				fmt.Fprintf(&out, "  - %s: %s %s\n", s.ID, s.Message, s.NextStep)
			}
		}
		for _, d := range r.Verification.Destinations {
			fmt.Fprintf(&out, "- Destination %s: resolution %s; scope %s; ownership %s; registration availability %s; reachability %s\n", markdownText(d.Host), d.Resolution, d.AddressScope, d.Ownership, d.RegistrationAvailability, d.Reachability)
		}
		for _, g := range r.Verification.Gaps {
			fmt.Fprintf(&out, "- Coverage: %s — %s\n", g.Code, g.Message)
		}
	}
	return out.String()
}
