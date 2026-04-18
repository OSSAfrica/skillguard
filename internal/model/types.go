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
	Findings       []Finding       `json:"findings"`
	Metadata       SkillMetadata   `json:"metadata"`
	CategoryScores []CategoryScore `json:"category_scores"`
}

type ScanReport struct {
	ScanTime    time.Time        `json:"scan_time"`
	TotalSkills int              `json:"total_skills"`
	Passed      int              `json:"passed"`
	Failed      int              `json:"failed"`
	Threshold   int              `json:"threshold"`
	Results     []AnalysisResult `json:"results"`
}
