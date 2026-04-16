package model

import "time"

type Severity string

const (
	SeverityHigh   Severity = "high"
	SeverityMedium Severity = "medium"
	SeverityLow    Severity = "low"
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
)

type Finding struct {
	Category    Category `json:"category"`
	Severity    Severity `json:"severity"`
	Description string   `json:"description"`
	Deduction   int      `json:"deduction"`
	Location    string   `json:"location,omitempty"`
	Pattern     string   `json:"pattern,omitempty"`
}

type SkillMetadata struct {
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	Location     string   `json:"location"`
	AllowedTools []string `json:"allowed_tools,omitempty"`
	Source       string   `json:"source,omitempty"`
	Triggers     []string `json:"triggers,omitempty"`
}

type AnalysisResult struct {
	SkillName string        `json:"skill_name"`
	FilePath  string        `json:"file_path"`
	Score     int           `json:"score"`
	Passed    bool          `json:"passed"`
	Findings  []Finding     `json:"findings"`
	Metadata  SkillMetadata `json:"metadata"`
}

type ScanReport struct {
	ScanTime    time.Time        `json:"scan_time"`
	TotalSkills int              `json:"total_skills"`
	Passed      int              `json:"passed"`
	Failed      int              `json:"failed"`
	Threshold   int              `json:"threshold"`
	Results     []AnalysisResult `json:"results"`
}
