package model

import "time"

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

type ScoreCategory string

const (
	CatSupplyChain  ScoreCategory = "supply_chain"
	CatSecurity     ScoreCategory = "security"
	CatQuality      ScoreCategory = "quality"
	CatMaintenance  ScoreCategory = "maintenance"
	CatTransparency ScoreCategory = "transparency"
)

type Category string

const (
	CategoryToolAccess      Category = "tool_access"
	CategoryShellExecution  Category = "shell_execution"
	CategoryFileAccess      Category = "file_access"
	CategoryNetwork         Category = "network"
	CategoryCredentials     Category = "credentials"
	CategoryPromptInjection Category = "prompt_injection"
	CategorySupplyChain     Category = "supply_chain"
	CategoryMetadata        Category = "metadata"
	CategoryObfuscatedCode  Category = "obfuscated_code"
	CategoryEvalUsage       Category = "eval_usage"
	CategoryGitDependency   Category = "git_dependency"
	CategoryHttpDependency  Category = "http_dependency"
	CategoryHiddenChars     Category = "hidden_characters"
	CategoryExternalScripts Category = "external_scripts"
	CategoryTelemetry       Category = "telemetry"
	CategoryTyposquatting   Category = "typosquatting"
	CategoryProtestware     Category = "protestware"
)

type Finding struct {
	Category    Category      `json:"category"`
	Severity    Severity      `json:"severity"`
	Description string        `json:"description"`
	Deduction   int           `json:"deduction"`
	Location    string        `json:"location,omitempty"`
	Pattern     string        `json:"pattern,omitempty"`
	ScoreCat    ScoreCategory `json:"score_category,omitempty"`
}

type CategoryScore struct {
	Category  ScoreCategory `json:"category"`
	Score     int           `json:"score"`
	Findings  int           `json:"findings"`
	Breakdown []Finding     `json:"breakdown,omitempty"`
}

type SkillMetadata struct {
	Name            string   `json:"name"`
	Description     string   `json:"description"`
	Location        string   `json:"location"`
	AllowedTools    []string `json:"allowed_tools,omitempty"`
	Source          string   `json:"source,omitempty"`
	Triggers        []string `json:"triggers,omitempty"`
	ReferencedFiles []string `json:"referenced_files,omitempty"`
}

type AnalysisResult struct {
	SkillName      string          `json:"skill_name"`
	FilePath       string          `json:"file_path"`
	OverallScore   int             `json:"overall_score"`
	Passed         bool            `json:"passed"`
	IsReference    bool            `json:"is_reference"`
	CriticalCount  int             `json:"critical_count"`
	Findings       []Finding       `json:"findings"`
	Metadata       SkillMetadata   `json:"metadata"`
	CategoryScores []CategoryScore `json:"category_scores"`
	Extraction     *Extraction     `json:"extraction,omitempty"`
}

type ScanReport struct {
	ScanTime     time.Time        `json:"scan_time"`
	TotalSkills  int              `json:"total_skills"`
	Passed       int              `json:"passed"`
	Failed       int              `json:"failed"`
	Threshold    int              `json:"threshold"`
	Results      []AnalysisResult `json:"results"`
	CoverageGaps []CoverageGap    `json:"coverage_gaps,omitempty"`
}

// SourceSpan locates untrusted evidence in the original input, before parsing
// frontmatter or removing Markdown delimiters. Lines are one-based and inclusive.
type SourceSpan struct {
	Source    string `json:"source"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
}

type CoverageGap struct {
	Code     string     `json:"code"`
	Message  string     `json:"message"`
	Location SourceSpan `json:"location"`
}

// Extraction describes static observations, never an execution authorization.
type Extraction struct {
	Status   string            `json:"status"`
	Commands []DocumentCommand `json:"commands"`
	Gaps     []CoverageGap     `json:"gaps"`
}

type DocumentCommand struct {
	Tool             string            `json:"tool"`
	Operation        string            `json:"operation"`
	Context          string            `json:"context"`
	Location         SourceSpan        `json:"location"`
	Evidence         string            `json:"evidence"` // bounded, reconstructed, untrusted data
	Dependencies     []Dependency      `json:"dependencies,omitempty"`
	Inputs           []DependencyInput `json:"inputs,omitempty"`
	Destinations     []Destination     `json:"destinations,omitempty"`
	Options          []CommandOption   `json:"options,omitempty"`
	PipedToExecution bool              `json:"piped_to_execution,omitempty"`
}

type CommandOption struct {
	Name  string `json:"name"`
	Value string `json:"value,omitempty"`
}

type Dependency struct {
	Ecosystem string   `json:"ecosystem"`
	Name      string   `json:"name,omitempty"`
	Specifier string   `json:"specifier,omitempty"`
	Source    string   `json:"source"` // registry, url, git, local, or unresolved
	Alias     string   `json:"alias,omitempty"`
	Extras    []string `json:"extras,omitempty"`
}

type DependencyInput struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	Status string `json:"status"` // referenced, readable, unavailable, or outside_boundary
}

type Destination struct {
	URL  string `json:"url"` // credentials, query, and fragment removed
	Role string `json:"role"`
}
