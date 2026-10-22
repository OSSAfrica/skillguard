// Package assess produces policy decisions for exact proposed actions. It never
// executes an action. Its inputs must come from a trusted enforcing harness.
package assess

import (
	"skillguard/internal/model"
	"skillguard/internal/verify"
	"time"
)

const RulesetVersion = "action-v1"
const MaxBytes = 1 << 20

type Request struct {
	TargetRoot     string            `json:"target_root"`
	SchemaVersion  int               `json:"schema_version"`
	Action         Action            `json:"action"`
	CWD            string            `json:"cwd"`
	Environment    map[string]string `json:"environment"`
	ContextProfile string            `json:"context_profile"`
	Inputs         []Input           `json:"inputs"`
	Provenance     []string          `json:"provenance,omitempty"`
}

type Action struct {
	Mode    string   `json:"mode"` // argv or bash
	Argv    []string `json:"argv,omitempty"`
	Command string   `json:"command,omitempty"`
}

type Input struct {
	Path string `json:"path"`
	Kind string `json:"kind"` // requirements, constraints, manifest, lockfile, config
}

type Policy struct {
	SchemaVersion int    `json:"schema_version"`
	ID            string `json:"id"`
	Version       string `json:"version"`
	MaxAgeSeconds int    `json:"max_age_seconds"`
	// Profiles attest an operator-enforced sandbox: exact supplied environment,
	// trusted binaries, no undeclared external config, modules or startup scripts.
	IsolatedProfiles         []string       `json:"isolated_profiles"`
	ReviewedActions          []Baseline     `json:"reviewed_actions"`
	ProhibitedPackages       []PackageRule  `json:"prohibited_packages,omitempty"`
	ProhibitedArtifactHashes []string       `json:"prohibited_artifact_hashes,omitempty"`
	RequireMetadata          bool           `json:"require_metadata"`
	Verification             *verify.Policy `json:"verification,omitempty"`
}

type Baseline struct {
	SubjectFingerprint     string    `json:"subject_fingerprint"`
	ContextFingerprint     string    `json:"context_fingerprint"`
	ReviewID               string    `json:"review_id"`
	ExpiresAt              time.Time `json:"expires_at"`
	AcceptMutableArtifacts bool      `json:"accept_mutable_artifacts,omitempty"`
}

type PackageRule struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
}

type Response struct {
	SchemaVersion       int                          `json:"schema_version"`
	EngineVersion       string                       `json:"engine_version"`
	RulesetVersion      string                       `json:"ruleset_version"`
	AssessedAt          time.Time                    `json:"assessed_at"`
	ExpiresAt           time.Time                    `json:"expires_at"`
	Status              string                       `json:"status"`
	Decision            string                       `json:"decision"`
	PolicyIdentity      string                       `json:"policy_id"`
	PolicyVersion       string                       `json:"policy_version"`
	PolicyFingerprint   string                       `json:"policy_fingerprint"`
	SubjectFingerprint  string                       `json:"subject_fingerprint"`
	ContextFingerprint  string                       `json:"context_fingerprint"`
	EvidenceFingerprint string                       `json:"evidence_fingerprint"`
	DecisionFingerprint string                       `json:"decision_fingerprint"`
	EvidenceTrust       string                       `json:"evidence_trust"`
	ReviewID            string                       `json:"review_id,omitempty"`
	Rules               []Rule                       `json:"rules"`
	Checks              []Check                      `json:"checks"`
	Inputs              []InputFact                  `json:"inputs"`
	Dependencies        []DependencyFact             `json:"dependencies"`
	Verification        *model.ReferenceVerification `json:"verification,omitempty"`
}

type Rule struct {
	ID          string           `json:"id"`
	Effect      string           `json:"effect"`
	Message     string           `json:"message"`
	Remediation string           `json:"remediation"`
	Location    model.SourceSpan `json:"location"`
}

type Check struct {
	ID       string `json:"id"`
	Required bool   `json:"required"`
	Status   string `json:"status"` // complete, partial, not_requested, error
}

type InputFact struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	SHA256 string `json:"sha256"`
	Status string `json:"status"`
}

type DependencyFact struct {
	Dependency     model.Dependency `json:"dependency"`
	Location       model.SourceSpan `json:"location"`
	ArtifactHashes []string         `json:"artifact_hashes"`
}

func (r Response) ExitCode() int {
	if r.Status != "complete" {
		return 2
	}
	if r.Decision != "allow" {
		return 1
	}
	return 0
}
