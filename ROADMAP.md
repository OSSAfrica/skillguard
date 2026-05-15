# SkillGuard Roadmap

> Last updated: May 2026

This document tracks the current progress of SkillGuard and outlines our future plans. Each phase builds on the last, moving from a local CLI scanner to a comprehensive ecosystem security platform.

**Legend:** ⬜ Not started | 🔄 In progress | ✅ Complete

---

## Achievements so far

- ✅ **CLI Scanner** — Multi-category security scoring engine (security, supply chain, transparency, quality, maintenance)
- ✅ **Detection Engine** — Shell execution, credential exposure, prompt injection, obfuscated code, hidden characters, untrusted URLs, HTTP/git dependencies, missing metadata, referenced script analysis
- ✅ **Scoring System** — Weighted scoring with exponential decay, configurable thresholds
- ✅ **CI/CD Integration** — GitHub Actions, GitLab CI, Docker Compose examples with threshold-based exit codes
- ✅ **Docker Support** — Chainguard distroless images (GHCR + Docker Hub)
- ✅ **Homebrew Distribution** — Tap via GoReleaser
- ✅ **Config Management** — Viper-based `~/.skillguard.yaml` with `config show/set` commands
- ✅ **JSON Reports** — Machine-readable output for downstream integration
- ✅ **GoReleaser Pipeline** — Multi-platform binaries (darwin/linux/windows × amd64/arm64)
- ✅ **OpenSSF Scorecard** — Security grading for the project itself
- ✅ **Provenance & Minimalism badges** — Supply chain security tracking

---

## Phase 1: Scan Infrastructure & Registry Intelligence

**Status:** 🔄 In progress
**Goal:** Move beyond local scans to discover, scan, and track skills across the ecosystem.

### 1.1 Registry Discovery CLI
- [ ] `skillguard registry add <url>` — register a skills source (skills.sh API, git repos)
- [ ] `skillguard registry list` — show registered sources and last scan status
- [ ] `skillguard registry scan` — run batch scan across all registered sources
- [ ] `skillguard registry sync` — incremental sync, only re-scan changed skills

### 1.2 skills.sh Integration
- [ ] skills.sh API integration — enumerate all published skills
- [ ] Clone and scan each skill's source
- [ ] Track skill versions and changelog diffs between scans

### 1.3 Database Layer (SQLite → D1)
- [ ] SQLite for local mode (CLI stores scan history locally)
- [ ] Schema: `skills`, `versions`, `scan_results`, `findings`, `registry_sources`
- [ ] Historical trend tracking — score changes across versions over time

### 1.4 Remote Repo Scanning
- [ ] `skillguard scan --repo <git-url>` — clone, scan, report, cleanup
- [ ] Support GitHub, GitLab, Bitbucket URLs
- [ ] Shallow clone for speed, optional branch/tag targeting

---

## Phase 2: SkillGuard.net — Public Security Dashboard

**Status:** ⬜ Not started
**Goal:** A socket.dev-style platform making skill security publicly discoverable.

### 2.1 Tech Stack
- **Backend:** Cloudflare Workers (Hono API) — scan ingestion, result storage, public API
- **Database:** Cloudflare D1 — PostgreSQL-compatible SQLite at the edge
- **Frontend:** TanStack Start (React SSR) — deployed on Cloudflare Pages
- **Queue:** Cloudflare Queues — async scan job processing
- **Scheduler:** Cloudflare Workers Cron Triggers — scheduled registry scans

### 2.2 Website Features
- [ ] **Search** — by skill name, author, or registry
- [ ] **Skill detail pages** — Full breakdown: overall score, category scores, findings, version history trend chart
- [ ] **Registry browse** — all skills from skills.sh with security ratings at a glance
- [ ] **Leaderboards** — safest skills, most improved, registry health rankings
- [ ] **Embeddable badges** — `[SkillGuard Score: A+]` for skill authors to put in their READMEs

### 2.3 Data Pipeline (Cloudflare)
- [ ] Cron Worker hits skills.sh API → enqueues scan jobs to Queue
- [ ] Worker processes job → clones repo → runs Go scanner (compiled to WASM or calls a dedicated Worker) → stores in D1
- [ ] Webhook endpoint for repos to trigger re-scan on push
- [ ] Public REST API: `GET /api/v1/skills/{id}`, `GET /api/v1/registry/{name}`

---

## Phase 3: Ecosystem Integration & Trust

**Status:** ⬜ Not started
**Goal:** Make SkillGuard the security standard for AI skill ecosystems.

### 3.1 Pre-publish Checks
- [ ] CLI plugin for skills.sh — auto-scan before publishing
- [ ] GitHub Action for skill repos — block merge if score drops below threshold
- [ ] IDE extension (VS Code) — real-time security linting while writing skills

### 3.2 Agent Runtime SDK
- [ ] Go/TypeScript SDK for agent frameworks to check SkillGuard API before loading a skill
- [ ] Policy engine — configurable rules (block skills < 60, require source_url, no shell access)
- [ ] OpenTelemetry tracing — audit log of loaded skills and their scores

### 3.3 Skill Authorship Verification
- [ ] Cryptographic signing of skill files (GPG or SSH keys)
- [ ] Skill author profiles on SkillGuard.dev — aggregate scores, verification status
- [ ] OAuth login for skill authors to claim their skills
- [ ] Community endorsement system — verified authors get trust badges

---

## Phase 4: Advanced Threat Detection

**Status:** ⬜ Not started
**Goal:** Go beyond static analysis for comprehensive security.

### 4.1 LLM-Assisted Analysis
- [ ] Send skill content to LLM for semantic threat detection
- [ ] Detect social engineering patterns, manipulation attempts, hidden instructions
- [ ] Compare stated intent vs actual behavior patterns
- [ ] Flag skills that try to override safety guidelines via prompt injection

### 4.2 Behavioral Analysis
- [ ] Sandboxed execution — run skills in container, monitor behavior
- [ ] Network egress monitoring — detect skills that phone home
- [ ] File system monitoring — detect unauthorized reads/writes

### 4.3 Vulnerability Database
- [ ] CVE-like tracking for skill vulnerabilities
- [ ] Advisory feed — notify users when a skill they use has new findings
- [ ] Integration with GitHub Security Advisories and OSV

---

## Phase 5: Enterprise & Governance

**Status:** ⬜ Not started

### 5.1 Organization Support
- [ ] Private scanning for internal skill registries
- [ ] Policy compliance dashboards
- [ ] SSO / RBAC for team access

### 5.2 Compliance & Reporting
- [ ] Exportable audit reports
- [ ] SOC 2 / ISO 27001 alignment
- [ ] SLA tracking for skill security posture
