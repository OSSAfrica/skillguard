package analyzer

import (
	"regexp"
	"strings"

	"skillguard/internal/model"
)

var (
	trustedDomains = []string{
		"github.com",
		"gitlab.com",
		"bitbucket.org",
		"npmjs.com",
		"pypi.org",
		"crates.io",
		"pkg.dev",
		"nuget.org",
		"rubygems.org",
		"packagist.org",
		"example.com",
	}

	trustedTLDs = []string{
		".vercel.app",
		".vercel.sh",
		".cloudflare.com",
		".google.com",
		".googleusercontent.com",
		".github.io",
		".readthedocs.io",
		".netlify.app",
		".herokuapp.com",
		".aws.amazon.com",
		".azure.com",
		".digitalocean.com",
	}

	shellPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)Bash\([^)]*\*:[^)]*\)`),
		regexp.MustCompile(`(?i)\b(exec|execute|run|spawn)\b`),
		regexp.MustCompile(`(?i)run\s+(?:command|shell|cmd)`),
		regexp.MustCompile(`(?i)\$\(`),
		regexp.MustCompile("(?i)`[^`]+`"),
		regexp.MustCompile(`(?i)subprocess|exec\.Command`),
	}

	filePatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(write|delete|remove|rm\s+-[rf]+\b|unlink)`),
		regexp.MustCompile(`(?i)\b(append|create|overwrite)\b.*\b(file|directory|folder)\b`),
		regexp.MustCompile(`(?i)\.write\(|\.delete\(|\.remove\(`),
	}

	credentialPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)`),
		regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]`),
		regexp.MustCompile(`(?i)(token|auth)[_-]?(secret|key)`),
		regexp.MustCompile(`(?i)AWS_ACCESS_KEY|AWS_SECRET`),
		regexp.MustCompile(`(?i)PRIVATE[_-]?KEY`),
		regexp.MustCompile(`(?i)(secret|credential)\s*[:=]`),
		regexp.MustCompile(`(?i)\$((AWS_|AZURE_|GCP_|STRIPE_|OPENAI_)[A-Z0-9_]+)`),
		regexp.MustCompile(`(?i)process\.env\.[A-Z_]+`),
	}

	urlPattern = regexp.MustCompile(`https?://[^\s\)\"\'\>]+\.?(?:\s|$)`)

	injectionPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(concat|join|interpolate|format)\s*\([^)]*user`),
		regexp.MustCompile(`(?i)(prompt|instruction|system)\s*=\s*[^;]+(\+|\.)`),
		regexp.MustCompile(`(?i)(system|user)\s+message\s*:\s*.*\+.*`),
		regexp.MustCompile(`(?i)replace.*\{.*\}`),
		regexp.MustCompile(`(?i)template\s*\(.*\$\{`),
	}
)

type Scorer struct {
	threshold int
}

func NewScorer(threshold int) *Scorer {
	return &Scorer{threshold: threshold}
}

func (s *Scorer) Analyze(path string, metadata *model.SkillMetadata, body string) *model.AnalysisResult {
	result := &model.AnalysisResult{
		SkillName: metadata.Name,
		FilePath:  path,
		Metadata:  *metadata,
		Findings:  []model.Finding{},
	}

	score := 100

	result.Findings = append(result.Findings, s.checkToolAccess(metadata)...)
	result.Findings = append(result.Findings, s.checkShellExecution(body)...)
	result.Findings = append(result.Findings, s.checkFileAccess(body)...)
	result.Findings = append(result.Findings, s.checkNetworkAccess(body)...)
	result.Findings = append(result.Findings, s.checkCredentials(body)...)
	result.Findings = append(result.Findings, s.checkPromptInjection(body)...)
	result.Findings = append(result.Findings, s.checkSupplyChain(metadata)...)
	result.Findings = append(result.Findings, s.checkMetadata(metadata)...)

	for _, f := range result.Findings {
		score -= f.Deduction
	}

	if score < 0 {
		score = 0
	}

	result.Score = score
	result.Passed = score >= s.threshold

	return result
}

func (s *Scorer) checkToolAccess(m *model.SkillMetadata) []model.Finding {
	var findings []model.Finding

	for _, tool := range m.AllowedTools {
		toolLower := strings.ToLower(tool)

		if strings.Contains(toolLower, "*") {
			findings = append(findings, model.Finding{
				Category:    model.CategoryToolAccess,
				Severity:    model.SeverityHigh,
				Description: "Unrestricted tool access with wildcard: " + tool,
				Deduction:   15,
				Pattern:     tool,
			})
		} else if strings.Contains(toolLower, "bash") || strings.Contains(toolLower, "shell") || strings.Contains(toolLower, "exec") {
			findings = append(findings, model.Finding{
				Category:    model.CategoryToolAccess,
				Severity:    model.SeverityHigh,
				Description: "Shell/command execution tool: " + tool,
				Deduction:   15,
				Pattern:     tool,
			})
		}
	}

	return findings
}

func (s *Scorer) checkShellExecution(body string) []model.Finding {
	var findings []model.Finding

	for _, pattern := range shellPatterns {
		if pattern.MatchString(body) {
			findings = append(findings, model.Finding{
				Category:    model.CategoryShellExecution,
				Severity:    model.SeverityHigh,
				Description: "Shell command execution pattern detected",
				Deduction:   20,
				Pattern:     pattern.String(),
			})
			break
		}
	}

	return findings
}

func (s *Scorer) checkFileAccess(body string) []model.Finding {
	var findings []model.Finding

	for _, pattern := range filePatterns {
		if pattern.MatchString(body) {
			findings = append(findings, model.Finding{
				Category:    model.CategoryFileAccess,
				Severity:    model.SeverityHigh,
				Description: "File write/delete operation detected",
				Deduction:   15,
				Pattern:     pattern.String(),
			})
			break
		}
	}

	return findings
}

func (s *Scorer) checkNetworkAccess(body string) []model.Finding {
	var findings []model.Finding

	urls := urlPattern.FindAllString(body, -1)
	seen := make(map[string]bool)

	for _, url := range urls {
		url = strings.TrimSpace(url)
		if seen[url] {
			continue
		}
		seen[url] = true

		if s.isUntrustedURL(url) {
			findings = append(findings, model.Finding{
				Category:    model.CategoryNetwork,
				Severity:    model.SeverityMedium,
				Description: "External URL to untrusted domain: " + url,
				Deduction:   10,
				Pattern:     url,
			})
		}
	}

	return findings
}

func (s *Scorer) isUntrustedURL(url string) bool {
	lowerURL := strings.ToLower(url)

	for _, domain := range trustedDomains {
		if strings.Contains(lowerURL, domain) {
			return false
		}
	}

	for _, tld := range trustedTLDs {
		if strings.HasSuffix(lowerURL, tld) {
			return false
		}
	}

	if strings.Contains(lowerURL, "localhost") || strings.Contains(lowerURL, "127.0.0.1") {
		return false
	}

	return true
}

func (s *Scorer) checkCredentials(body string) []model.Finding {
	var findings []model.Finding

	for _, pattern := range credentialPatterns {
		matches := pattern.FindAllString(body, -1)
		for _, match := range matches {
			findings = append(findings, model.Finding{
				Category:    model.CategoryCredentials,
				Severity:    model.SeverityHigh,
				Description: "Potential credential or secret reference detected",
				Deduction:   20,
				Pattern:     match,
			})
		}
	}

	return findings
}

func (s *Scorer) checkPromptInjection(body string) []model.Finding {
	var findings []model.Finding

	for _, pattern := range injectionPatterns {
		matches := pattern.FindAllString(body, -1)
		for _, match := range matches {
			findings = append(findings, model.Finding{
				Category:    model.CategoryPromptInjection,
				Severity:    model.SeverityMedium,
				Description: "Potential prompt injection pattern detected",
				Deduction:   15,
				Pattern:     match,
			})
		}
	}

	return findings
}

func (s *Scorer) checkSupplyChain(m *model.SkillMetadata) []model.Finding {
	var findings []model.Finding

	if m.Source == "" {
		findings = append(findings, model.Finding{
			Category:    model.CategorySupplyChain,
			Severity:    model.SeverityLow,
			Description: "No source URL provided - unverifiable skill",
			Deduction:   10,
		})
	}

	return findings
}

func (s *Scorer) checkMetadata(m *model.SkillMetadata) []model.Finding {
	var findings []model.Finding

	if m.Description == "" {
		findings = append(findings, model.Finding{
			Category:    model.CategoryMetadata,
			Severity:    model.SeverityLow,
			Description: "Missing description - reduces transparency",
			Deduction:   5,
		})
	}

	if len(m.Triggers) == 0 {
		findings = append(findings, model.Finding{
			Category:    model.CategoryMetadata,
			Severity:    model.SeverityLow,
			Description: "No trigger keywords defined - unclear when skill activates",
			Deduction:   5,
		})
	}

	return findings
}
