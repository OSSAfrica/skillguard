package model

import "time"

// ReferenceVerification reports observations, not artifact trust or permission.
type ReferenceVerification struct {
	Status       string                   `json:"status"`
	Packages     []PackageObservation     `json:"packages"`
	Destinations []DestinationObservation `json:"destinations"`
	Gaps         []CoverageGap            `json:"gaps"`
}

type VerificationSignal struct {
	ID       string `json:"id"`
	Message  string `json:"message"`
	NextStep string `json:"next_step"`
}

type PackageObservation struct {
	Ecosystem              string               `json:"ecosystem"`
	Name                   string               `json:"name"`
	RequestedSpecifier     string               `json:"requested_specifier,omitempty"`
	Registry               string               `json:"registry,omitempty"`
	SourceSelection        string               `json:"source_selection"`
	MetadataURL            string               `json:"metadata_url,omitempty"`
	State                  string               `json:"state"`
	Reason                 string               `json:"reason,omitempty"`
	VersionState           string               `json:"version_state"`
	Version                string               `json:"version,omitempty"`
	PublishedAt            *time.Time           `json:"published_at,omitempty"`
	ClaimedRepositoryURL   string               `json:"claimed_repository_url,omitempty"`
	Provenance             string               `json:"provenance"`
	Identity               string               `json:"identity"`
	MalwareCheck           string               `json:"malware_check"`
	IntelligenceSource     string               `json:"intelligence_source,omitempty"`
	ObservedAt             time.Time            `json:"observed_at"`
	ExpiresAt              *time.Time           `json:"expires_at,omitempty"`
	FromCache              bool                 `json:"from_cache"`
	StaleEvidenceDiscarded bool                 `json:"stale_evidence_discarded,omitempty"`
	Location               SourceSpan           `json:"location"`
	Signals                []VerificationSignal `json:"signals,omitempty"`
}

type DestinationObservation struct {
	URL                      string               `json:"url"`
	Host                     string               `json:"host,omitempty"`
	Resolution               string               `json:"resolution"`
	AddressScope             string               `json:"address_scope"`
	Ownership                string               `json:"ownership"`
	RegistrationAvailability string               `json:"registration_availability"`
	Reachability             string               `json:"reachability"`
	ObservedAt               time.Time            `json:"observed_at"`
	Location                 SourceSpan           `json:"location"`
	Signals                  []VerificationSignal `json:"signals,omitempty"`
}
