package analyzer

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
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
		"github.io",
		"readthedocs.io",
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

	urlPattern = regexp.MustCompile(`https?://[^\s)"'>]+\.?(?:\s|$)`)

	injectionPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(concat|join|interpolate|format)\s*\([^)]*user`),
		regexp.MustCompile(`(?i)(prompt|instruction|system)\s*=\s*[^;]+([+.])`),
		regexp.MustCompile(`(?i)(system|user)\s+message\s*:\s*.*\+.*`),
		regexp.MustCompile(`(?i)replace.*\{.*}`),
		regexp.MustCompile(`(?i)template\s*\(.*\$\{`),
	}

	obfuscatedPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)eval\s*\(`),
		regexp.MustCompile(`(?i)Function\s*\(`),
		regexp.MustCompile(`(?i)setTimeout\s*\(\s*['"]`),
		regexp.MustCompile(`(?i)setInterval\s*\(\s*['"]`),
		regexp.MustCompile("(?i)exec\\s*\\(\\s*[`']"),
		regexp.MustCompile(`(?i)\.replace\(.*/[a-z]+`),
		regexp.MustCompile(`(?i)atob\(|btoa\(`),
		regexp.MustCompile(`(?i)fromCharCode`),
		regexp.MustCompile(`(?i)(unescape|encodeURIComponent|decodeURIComponent)\s*\(`),
	}

	gitDependencyPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)git\s+(clone|checkout|fetch|pull)`),
		regexp.MustCompile(`(?i)git://\S+`),
		regexp.MustCompile(`(?i)git\+https://`),
		regexp.MustCompile(`(?i)GIT_SSH_COMMAND`),
		regexp.MustCompile(`(?i)\.git/config`),
		regexp.MustCompile(`(?i)git\s+submodule`),
	}

	httpDependencyPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)curl\s+.*\|\s*sh`),
		regexp.MustCompile(`(?i)wget\s+.*\|\s*sh`),
		regexp.MustCompile(`(?i)curl\s+.*\|\s*bash`),
		regexp.MustCompile(`(?i)https?://\S+/install`),
		regexp.MustCompile(`(?i)https?://\S+\.sh`),
		regexp.MustCompile(`(?i)https?://\S+\.py.*exec`),
		regexp.MustCompile(`(?i)os\.system\s*\(\s*['"]http`),
		regexp.MustCompile(`(?i)requests\.get\s*\(\s*['"]http`),
		regexp.MustCompile(`(?i)subprocess.*http`),
	}

	telemetryPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)analytics|tracking|telemetry|metrics`),
		regexp.MustCompile(`(?i)mixpanel|segment|amplitude|google-analytics`),
		regexp.MustCompile(`(?i)send\s+(event|metric|data)\s+to`),
		regexp.MustCompile(`(?i)log\.(info|debug|warn).*\b(url|ip|email|user)`),
	}

	hiddenCharPatterns = []*regexp.Regexp{
		regexp.MustCompile(`[\x00-\x08\x0B\x0C\x0E-\x1F]`),
		regexp.MustCompile("[\u200B-\u200F\u2028-\u202F]"),
		regexp.MustCompile("\uFEFF"),
		regexp.MustCompile("[\u202A-\u202E]"),
		regexp.MustCompile("[\u2060-\u2064]"),
	}

	homoglyphPatterns = []*regexp.Regexp{
		regexp.MustCompile(`[а-яА-ЯёЁ]|[À-ÿ]|[Α-Ωα-ω]`),
	}

	referencePatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\[([^]]+)]\(([^)]+\.(py|js|ts|sh|rb|go|rs))\)`),
		regexp.MustCompile(`(?i)scripts?/[^/\s]+\.(py|js|ts|sh|rb|go|rs)`),
		regexp.MustCompile(`(?i)import\s+(?:from\s+)?['"](\.\./)?[^'"]+\.(py|js|ts)`),
		regexp.MustCompile(`(?i)require\s*\(\s*['"](\.\./)?[^'"]+\.(js|ts)`),
		regexp.MustCompile(`(?i)<script\s+src=`),
		regexp.MustCompile(`(?i)source\s+(\S+\.(sh|bash))`),
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
		SkillName:      metadata.Name,
		FilePath:       path,
		Metadata:       *metadata,
		Findings:       []model.Finding{},
		CategoryScores: s.initCategoryScores(),
	}

	metadata.ReferencedFiles = s.extractReferencedFiles(body)
	result.Findings = append(result.Findings, s.checkToolAccess(metadata)...)
	result.Findings = append(result.Findings, s.checkShellExecution(body)...)
	result.Findings = append(result.Findings, s.checkFileAccess(body)...)
	result.Findings = append(result.Findings, s.checkNetworkAccess(body)...)
	result.Findings = append(result.Findings, s.checkCredentials(body)...)
	result.Findings = append(result.Findings, s.checkPromptInjection(body)...)
	result.Findings = append(result.Findings, s.checkSupplyChain(metadata)...)
	result.Findings = append(result.Findings, s.checkMetadata(metadata)...)
	result.Findings = append(result.Findings, s.checkObfuscatedCode(body)...)
	result.Findings = append(result.Findings, s.checkGitDependencies(body)...)
	result.Findings = append(result.Findings, s.checkHttpDependencies(body)...)
	result.Findings = append(result.Findings, s.checkTelemetry(body)...)
	result.Findings = append(result.Findings, s.checkHiddenCharacters(body)...)

	if len(metadata.ReferencedFiles) > 0 {
		referencedFindings := s.analyzeReferencedScripts(path, metadata.ReferencedFiles)
		result.Findings = append(result.Findings, referencedFindings...)
	}

	result.CategoryScores = s.calculateCategoryScores(result.Findings)

	overallScore := s.calculateOverallScore(result.CategoryScores)
	result.OverallScore = overallScore
	result.Passed = overallScore >= s.threshold

	return result
}

func (s *Scorer) AnalyzeReference(path string, body string) *model.AnalysisResult {
	name := filepath.Base(path)
	if ext := filepath.Ext(name); ext != "" {
		name = strings.TrimSuffix(name, ext)
	}

	result := &model.AnalysisResult{
		SkillName:      name,
		FilePath:       path,
		IsReference:    true,
		Findings:       []model.Finding{},
		CategoryScores: s.initCategoryScores(),
	}

	result.Findings = append(result.Findings, s.checkShellExecution(body)...)
	result.Findings = append(result.Findings, s.checkFileAccess(body)...)
	result.Findings = append(result.Findings, s.checkNetworkAccess(body)...)
	result.Findings = append(result.Findings, s.checkCredentials(body)...)
	result.Findings = append(result.Findings, s.checkObfuscatedCode(body)...)
	result.Findings = append(result.Findings, s.checkHttpDependencies(body)...)
	result.Findings = append(result.Findings, s.checkHiddenCharacters(body)...)

	result.CategoryScores = s.calculateCategoryScores(result.Findings)

	overallScore := s.calculateOverallScore(result.CategoryScores)
	result.OverallScore = overallScore
	result.Passed = overallScore >= s.threshold

	return result
}

func (s *Scorer) initCategoryScores() []model.CategoryScore {
	return []model.CategoryScore{
		{Category: model.CatSupplyChain, Score: 100, Findings: 0},
		{Category: model.CatSecurity, Score: 100, Findings: 0},
		{Category: model.CatQuality, Score: 100, Findings: 0},
		{Category: model.CatMaintenance, Score: 100, Findings: 0},
		{Category: model.CatTransparency, Score: 100, Findings: 0},
	}
}

func (s *Scorer) calculateCategoryScores(findings []model.Finding) []model.CategoryScore {
	scores := s.initCategoryScores()

	counts := map[model.Category]int{}
	for _, f := range findings {
		counts[f.Category]++
	}

	for _, f := range findings {
		cat := f.ScoreCat
		if cat == "" {
			cat = s.mapFindingToScoreCategory(f.Category)
		}

		for i := range scores {
			if scores[i].Category == cat {
				scores[i].Findings++
				scores[i].Breakdown = append(scores[i].Breakdown, f)
				deduction := s.calculateDeductionWithDecay(f.Severity, counts[f.Category])
				scores[i].Score -= int(deduction)
				break
			}
		}
	}

	for i := range scores {
		if scores[i].Score < 0 {
			scores[i].Score = 0
		}
	}

	return scores
}

func (s *Scorer) mapFindingToScoreCategory(cat model.Category) model.ScoreCategory {
	switch cat {
	case model.CategorySupplyChain, model.CategoryExternalScripts, model.CategoryGitDependency:
		return model.CatSupplyChain
	case model.CategoryShellExecution, model.CategoryFileAccess, model.CategoryNetwork,
		model.CategoryCredentials, model.CategoryObfuscatedCode, model.CategoryEvalUsage,
		model.CategoryHiddenChars, model.CategoryHttpDependency:
		return model.CatSecurity
	case model.CategoryToolAccess:
		return model.CatQuality
	case model.CategoryTelemetry, model.CategoryProtestware:
		return model.CatMaintenance
	case model.CategoryMetadata, model.CategoryPromptInjection:
		return model.CatTransparency
	default:
		return model.CatSecurity
	}
}

func (s *Scorer) calculateDeductionWithDecay(sev model.Severity, count int) float64 {
	baseDeduction := s.getBaseDeduction(sev)

	switch sev {
	case model.SeverityCritical:
		return baseDeduction * math.Exp(-float64(count-1)*10)
	case model.SeverityHigh:
		return baseDeduction * math.Exp(-float64(count-1)*1)
	case model.SeverityMedium:
		return baseDeduction * math.Exp(-float64(count-1)*0.05)
	case model.SeverityLow:
		return baseDeduction * math.Exp(-float64(count-1)*0.025)
	default:
		return float64(baseDeduction)
	}
}

func (s *Scorer) getBaseDeduction(sev model.Severity) float64 {
	switch sev {
	case model.SeverityCritical:
		return 40
	case model.SeverityHigh:
		return 20
	case model.SeverityMedium:
		return 10
	case model.SeverityLow:
		return 5
	default:
		return 10
	}
}

func (s *Scorer) calculateOverallScore(catScores []model.CategoryScore) int {
	totalWeight := 0.0
	weightedSum := 0.0

	weights := map[model.ScoreCategory]float64{
		model.CatSupplyChain:  2.0,
		model.CatSecurity:     3.0,
		model.CatQuality:      1.5,
		model.CatMaintenance:  1.0,
		model.CatTransparency: 1.5,
	}

	for _, cs := range catScores {
		w := weights[cs.Category]
		weightedSum += float64(cs.Score) * w
		totalWeight += w
	}

	if totalWeight == 0 {
		return 100
	}

	score := int(math.Round(weightedSum / totalWeight))
	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}

	return score
}

func (s *Scorer) extractReferencedFiles(body string) []string {
	var files []string
	seen := make(map[string]bool)

	for _, pattern := range referencePatterns {
		matches := pattern.FindAllStringSubmatch(body, -1)
		for _, match := range matches {
			if len(match) > 1 {
				file := match[len(match)-1]
				if !seen[file] {
					seen[file] = true
					files = append(files, file)
				}
			}
		}
	}

	return files
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
				ScoreCat:    model.CatQuality,
			})
		} else if strings.Contains(toolLower, "bash") || strings.Contains(toolLower, "shell") || strings.Contains(toolLower, "exec") {
			findings = append(findings, model.Finding{
				Category:    model.CategoryToolAccess,
				Severity:    model.SeverityHigh,
				Description: "Shell/command execution tool: " + tool,
				Deduction:   15,
				Pattern:     tool,
				ScoreCat:    model.CatQuality,
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
				ScoreCat:    model.CatSecurity,
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
				ScoreCat:    model.CatSecurity,
			})
			break
		}
	}

	return findings
}

func (s *Scorer) checkNetworkAccess(body string) []model.Finding {
	var findings []model.Finding
	seen := make(map[string]bool)

	urls := urlPattern.FindAllString(body, -1)
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
				ScoreCat:    model.CatSecurity,
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
		if pattern.MatchString(body) {
			findings = append(findings, model.Finding{
				Category:    model.CategoryCredentials,
				Severity:    model.SeverityHigh,
				Description: "Potential credential or secret reference detected",
				Deduction:   20,
				Pattern:     pattern.String(),
				ScoreCat:    model.CatSecurity,
			})
			break
		}
	}

	return findings
}

func (s *Scorer) checkPromptInjection(body string) []model.Finding {
	var findings []model.Finding

	for _, pattern := range injectionPatterns {
		if pattern.MatchString(body) {
			findings = append(findings, model.Finding{
				Category:    model.CategoryPromptInjection,
				Severity:    model.SeverityMedium,
				Description: "Potential prompt injection pattern detected",
				Deduction:   15,
				Pattern:     pattern.String(),
				ScoreCat:    model.CatTransparency,
			})
			break
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
			ScoreCat:    model.CatSupplyChain,
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
			ScoreCat:    model.CatTransparency,
		})
	}

	if len(m.Triggers) == 0 {
		findings = append(findings, model.Finding{
			Category:    model.CategoryMetadata,
			Severity:    model.SeverityLow,
			Description: "No trigger keywords defined - unclear when skill activates",
			Deduction:   5,
			ScoreCat:    model.CatTransparency,
		})
	}

	return findings
}

func (s *Scorer) checkObfuscatedCode(body string) []model.Finding {
	var findings []model.Finding

	for _, pattern := range obfuscatedPatterns {
		if pattern.MatchString(body) {
			findings = append(findings, model.Finding{
				Category:    model.CategoryObfuscatedCode,
				Severity:    model.SeverityCritical,
				Description: "Obfuscated code pattern detected (eval/Function/setTimeout)",
				Deduction:   30,
				Pattern:     pattern.String(),
				ScoreCat:    model.CatSecurity,
			})
			break
		}
	}

	return findings
}

func (s *Scorer) checkGitDependencies(body string) []model.Finding {
	var findings []model.Finding

	for _, pattern := range gitDependencyPatterns {
		if pattern.MatchString(body) {
			findings = append(findings, model.Finding{
				Category:    model.CategoryGitDependency,
				Severity:    model.SeverityMedium,
				Description: "Git dependency or operation detected",
				Deduction:   15,
				Pattern:     pattern.String(),
				ScoreCat:    model.CatSupplyChain,
			})
			break
		}
	}

	return findings
}

func (s *Scorer) checkHttpDependencies(body string) []model.Finding {
	var findings []model.Finding

	for _, pattern := range httpDependencyPatterns {
		if pattern.MatchString(body) {
			findings = append(findings, model.Finding{
				Category:    model.CategoryExternalScripts,
				Severity:    model.SeverityCritical,
				Description: "HTTP dependency with code execution risk detected",
				Deduction:   35,
				Pattern:     pattern.String(),
				ScoreCat:    model.CatSupplyChain,
			})
			break
		}
	}

	return findings
}

func (s *Scorer) checkTelemetry(body string) []model.Finding {
	var findings []model.Finding

	for _, pattern := range telemetryPatterns {
		if pattern.MatchString(body) {
			findings = append(findings, model.Finding{
				Category:    model.CategoryTelemetry,
				Severity:    model.SeverityLow,
				Description: "Potential telemetry or analytics detected",
				Deduction:   5,
				Pattern:     pattern.String(),
				ScoreCat:    model.CatMaintenance,
			})
			break
		}
	}

	return findings
}

func (s *Scorer) checkHiddenCharacters(body string) []model.Finding {
	var findings []model.Finding

	for _, pattern := range hiddenCharPatterns {
		if pattern.MatchString(body) {
			matches := pattern.FindAllString(body, -1)
			if len(matches) > 0 {
				findings = append(findings, model.Finding{
					Category:    model.CategoryHiddenChars,
					Severity:    model.SeverityHigh,
					Description: "Hidden characters detected (zero-width, RTL, control chars)",
					Deduction:   25,
					Pattern:     fmt.Sprintf("Found %d hidden character(s)", len(matches)),
					ScoreCat:    model.CatSecurity,
				})
				break
			}
		}
	}

	reversePattern := regexp.MustCompile(`(\xE2\x80\x8E|\xE2\x80\x8F|\xE2\x80\xAA|\xE2\x80\xAB)`)
	if reversePattern.MatchString(body) {
		findings = append(findings, model.Finding{
			Category:    model.CategoryHiddenChars,
			Severity:    model.SeverityHigh,
			Description: "RTL (right-to-left) override characters detected",
			Deduction:   25,
			Pattern:     "RTL override",
			ScoreCat:    model.CatSecurity,
		})
	}

	homoglyphs := homoglyphPatterns[0].FindAllString(body, -1)
	if len(homoglyphs) > 10 {
		findings = append(findings, model.Finding{
			Category:    model.CategoryHiddenChars,
			Severity:    model.SeverityMedium,
			Description: "Potential homoglyph characters detected (cyrillic lookalikes)",
			Deduction:   15,
			Pattern:     fmt.Sprintf("Found %d potential homoglyph(s)", len(homoglyphs)),
			ScoreCat:    model.CatSecurity,
		})
	}

	return findings
}

func (s *Scorer) GetReferencedScriptsPath(basePath string, files []string) []string {
	var scripts []string
	for _, f := range files {
		ext := strings.ToLower(filepath.Ext(f))
		if ext == ".py" || ext == ".js" || ext == ".ts" || ext == ".sh" || ext == ".rb" || ext == ".go" || ext == ".rs" {
			scripts = append(scripts, f)
		}
	}
	return scripts
}

func (s *Scorer) analyzeReferencedScripts(basePath string, files []string) []model.Finding {
	var findings []model.Finding

	baseDir := filepath.Dir(basePath)
	scriptFiles := s.GetReferencedScriptsPath(basePath, files)

	for _, scriptFile := range scriptFiles {
		var scriptPath string
		if filepath.IsAbs(scriptFile) {
			scriptPath = scriptFile
		} else {
			scriptPath = filepath.Join(baseDir, scriptFile)
		}

		content, err := os.ReadFile(scriptPath)
		if err != nil {
			continue
		}

		scriptContent := string(content)

		for _, pattern := range httpDependencyPatterns {
			if pattern.MatchString(scriptContent) {
				findings = append(findings, model.Finding{
					Category:    model.CategoryExternalScripts,
					Severity:    model.SeverityCritical,
					Description: "HTTP dependency with code execution risk in referenced script: " + scriptFile,
					Deduction:   40,
					Pattern:     pattern.String(),
					Location:    scriptPath,
					ScoreCat:    model.CatSupplyChain,
				})
				break
			}
		}

		for _, pattern := range shellPatterns {
			if pattern.MatchString(scriptContent) {
				findings = append(findings, model.Finding{
					Category:    model.CategoryShellExecution,
					Severity:    model.SeverityHigh,
					Description: "Shell execution pattern in referenced script: " + scriptFile,
					Deduction:   25,
					Pattern:     pattern.String(),
					Location:    scriptPath,
					ScoreCat:    model.CatSecurity,
				})
				break
			}
		}

		for _, pattern := range credentialPatterns {
			if pattern.MatchString(scriptContent) {
				findings = append(findings, model.Finding{
					Category:    model.CategoryCredentials,
					Severity:    model.SeverityHigh,
					Description: "Credential pattern in referenced script: " + scriptFile,
					Deduction:   25,
					Pattern:     pattern.String(),
					Location:    scriptPath,
					ScoreCat:    model.CatSecurity,
				})
				break
			}
		}

		for _, pattern := range obfuscatedPatterns {
			if pattern.MatchString(scriptContent) {
				findings = append(findings, model.Finding{
					Category:    model.CategoryObfuscatedCode,
					Severity:    model.SeverityCritical,
					Description: "Obfuscated code in referenced script: " + scriptFile,
					Deduction:   35,
					Pattern:     pattern.String(),
					Location:    scriptPath,
					ScoreCat:    model.CatSecurity,
				})
				break
			}
		}
	}

	return findings
}
