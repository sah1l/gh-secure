# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

`gh-secure` is a GitHub CLI extension (invoked as `gh secure`) that audits and hardens GitHub repository security settings via the GitHub REST API. It manages branch protection, rulesets, merge strategies, secret scanning, vulnerability alerts, and community files.

## Build & Run

```powershell
go build -o gh-secure.exe .          # Build the binary
go run . status --repo owner/name    # Run without building
go vet ./...                         # Lint
```

There are no tests in this project yet. No Makefile — just standard `go build`.

The extension requires `gh` CLI to be installed and authenticated (it uses `github.com/cli/go-gh/v2` for API auth and repo detection).

## Architecture

### Entry Point & CLI

- `main.go` → `cmd.Execute()` — Cobra CLI with four subcommands
- `cmd/root.go` — Root command, global `--repo` flag
- `cmd/status.go` — Reads and displays all security settings (branch protection, rulesets, security features, community files)
- `cmd/audit.go` — Runs 12 security checks and scores A-F
- `cmd/init.go` — Interactive wizard or preset-based configuration, then applies settings via API
- `cmd/reset.go` — Removes rulesets, branch protection, and/or security features

### Packages

**`pkg/github`** — GitHub REST API client wrapping `cli/go-gh/v2`. All API calls go through `Client` methods. Key files split by domain:
- `client.go` — Client struct, REST helpers (Get/Put/Patch/Post/Delete), repo path builder
- `repo.go` — Repo settings, visibility, merge strategies
- `branch.go` — Branch protection CRUD, `isHTTPError` helper
- `rulesets.go` — Ruleset CRUD, `SupportsRulesets()` feature detection, `BuildProtectionRuleset()` builder
- `security.go` — Vulnerability alerts, automated security fixes, secret scanning
- `files.go` — File existence checks and create/update via Contents API

**`pkg/config`** — Configuration types and presets:
- `types.go` — `Config` struct (the central data model for what to apply)
- `presets.go` — Three built-in presets: `oss`, `private`, `strict`
- `yaml.go` — YAML marshal/unmarshal for configs

**`pkg/audit`** — `RunAudit()` takes gathered data and returns `AuditReport` with 12 checks, each with severity (critical/warning/info) and fix suggestions. Scoring: A (>=90%), B (>=75%), C (>=60%), D (>=40%), F (<40%).

**`pkg/wizard`** — Interactive `huh` forms that produce a `config.Config`. Sections: visibility → license/community files (public only) → merge strategy → branch protection → security features.

**`pkg/templates`** — Template strings for generated files (CONTRIBUTING.md, SECURITY.md, CODE_OF_CONDUCT.md, dependabot.yml).

### Key Patterns

- **Ruleset/branch protection fallback**: `init` prefers rulesets when `SupportsRulesets()` returns true, otherwise falls back to legacy branch protection API. The config uses `~DEFAULT_BRANCH~` as a placeholder replaced at apply time.
- **TUI**: Uses `charmbracelet/huh` for interactive forms and `charmbracelet/lipgloss` for styled terminal output.
- **API client**: All GitHub API calls go through `Client` methods that return domain-specific Go structs. The client auto-detects the current repo from git context or accepts `--repo owner/name`.
