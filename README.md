# gh-secure

A GitHub CLI extension that hardens any GitHub repository in under 60 seconds. Audit and apply security best practices — branch protection, rulesets, merge strategies, secret scanning, and more.

## Installation

```bash
gh extension install sah1l/gh-secure
```

## Usage

```bash
# Show security posture of current repo
gh secure status

# Target a specific repo
gh secure status --repo owner/repo

# Audit security and get a score
gh secure audit

# Interactive security setup
gh secure init

# Apply a preset (oss, private, strict)
gh secure init --preset oss

# Export security config to a file
gh secure export -o config.yaml

# Import config to another repo
gh secure import -f config.yaml --repo owner/other-repo

# Remove security settings
gh secure reset
```

## Commands

### `gh secure status`

Displays the full security posture of a repository — visibility, branch protection, rulesets, security features, and community files.

```
$ gh secure status --repo sahil/devcred

sahil/devcred (public)

  ✓ License: MIT License
  · Default branch: master
  · Merge: squash, merge, rebase
  ✗ Delete branch on merge

  Branch Protection
    ✓ master: protected
      Reviews: 1, require CODEOWNERS
      ✓ Force push blocked

  Rulesets
    · none

  Security
    ✗ Vulnerability alerts
    ✗ Automated security fixes
    ✓ Secret scanning
    ✓ Secret scanning push protection

  Community Files
    ✗ .github/dependabot.yml
    ✗ CODEOWNERS
    ✗ .github/CODEOWNERS
    ✓ LICENSE
    ✓ CONTRIBUTING.md
    ✓ SECURITY.md
    ✗ CODE_OF_CONDUCT.md
```

Use `--json` for machine-readable output.

### `gh secure audit`

Runs 12 security checks and scores your repository A through F.

```bash
gh secure audit --repo owner/repo
```

Checks include: license, branch protection, required reviews, force push blocked, deletion blocked, delete-on-merge, vulnerability alerts, automated security fixes, secret scanning, security policy, dependabot config, and single merge strategy.

### `gh secure init`

Interactive wizard to configure repository security. Walks through visibility, license, merge strategy, branch protection/rulesets, and security features.

```bash
# Interactive mode
gh secure init

# Apply a preset
gh secure init --preset oss      # public, MIT, 1 review, dependabot, community files
gh secure init --preset private  # private, 2 reviews, dependabot
gh secure init --preset strict   # private, 2 reviews, signed commits, linear history, CODEOWNERS
```

Uses rulesets when available, falls back to legacy branch protection automatically.

### `gh secure export`

Export a repository's security configuration as YAML. Useful for backing up settings or replicating them across repos.

```bash
# Print config to stdout
gh secure export --repo owner/repo

# Save to a file
gh secure export --repo owner/repo -o config.yaml
```

### `gh secure import`

Apply a previously exported configuration to a repository. Prompts before overwriting existing files; use `--yes` to skip all prompts for CI.

```bash
# Apply config interactively
gh secure import -f config.yaml --repo owner/other-repo

# Apply without prompts (CI-friendly)
gh secure import -f config.yaml --repo owner/other-repo --yes
```

### `gh secure reset`

Remove security settings selectively or completely.

```bash
# Interactive selection
gh secure reset

# Remove all rulesets
gh secure reset --rules

# Remove branch protection
gh secure reset --protection

# Remove everything (requires typing RESET to confirm)
gh secure reset --all
```

## Flags

| Flag | Scope | Description |
|------|-------|-------------|
| `--repo owner/name` | Global | Target a specific repository |
| `--json` | status, audit | Output as JSON |
| `--preset name` | init | Apply a preset (oss, private, strict) |
| `--force` | init | Reset existing settings before applying |
| `--output`, `-o` | export | Write YAML to file instead of stdout |
| `--file`, `-f` | import | Path to YAML config file (required) |
| `--yes`, `-y` | import | Skip all confirmation prompts |
| `--all` | reset | Remove all security settings |
| `--rules` | reset | Remove rulesets only |
| `--protection` | reset | Remove branch protection only |

## Local Development

### Prerequisites

- [Go](https://go.dev/) 1.21+
- [GitHub CLI](https://cli.github.com/) (`gh`) installed and authenticated

### Build

```bash
go build -o gh-secure .
```

On Windows, specify the `.exe` extension:

```powershell
go build -o gh-secure.exe .
```

### Run locally

```bash
# Run without building
go run . status --repo owner/repo

# Or use the built binary
./gh-secure status --repo owner/repo
```

### Install as a local gh extension

```bash
# Link the local build into gh's extension directory
gh extension install .
```

### Lint

```bash
go vet ./...
```

### Format

```bash
go fmt ./...
```

## Requirements

- [GitHub CLI](https://cli.github.com/) (`gh`) installed and authenticated
- Repository admin access for write operations

## License

MIT
