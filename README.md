# gh-secure

A GitHub CLI extension that hardens any GitHub repository in under 60 seconds. Audit and apply security best practices — branch protection, rulesets, merge strategies, secret scanning, and more.

## Installation

```bash
gh extension install sahilxyz/gh-secure
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
| `--all` | reset | Remove all security settings |
| `--rules` | reset | Remove rulesets only |
| `--protection` | reset | Remove branch protection only |

## Requirements

- [GitHub CLI](https://cli.github.com/) (`gh`) installed and authenticated
- Repository admin access for write operations

## License

MIT
