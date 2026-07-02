# Roadmap

Ideas under consideration. No timelines, no promises; roughly ordered by how likely they are to happen. Feedback via issues is appreciated, especially if one of these would be useful to you.

## gh-secure

Features that belong in this extension.

### Dependency risk checks

Extend the audit with supply-chain checks: unmaintained dependencies (age of last release), single-maintainer packages, packages with install scripts, and license conflicts. Same A to F grading, either as new audit checks or a dedicated `gh secure deps` subcommand.

### Repo file baseline

Extend export/import beyond settings to files. Export the linter configs, `.editorconfig`, `.gitignore`, PR templates, and CODEOWNERS from a well-configured repo as a baseline, then apply it to any other repo via PR. Same "secure one repo, copy it everywhere" workflow, applied to the working tree.

## Future tools

Separate tools built on the same philosophy: find a scattered, tedious workflow and collapse it into one command.

### gh-tidy

Repo janitor. Audit cruft: stale branches, merged-but-undeleted branches, abandoned draft PRs, unused Actions secrets, dead workflows. `gh tidy audit` reports, `gh tidy clean --yes` fixes.

### gh-ci-audit

Find wasted GitHub Actions time and money: missing caches, no concurrency groups, workflows triggered on paths they don't need, jobs that could be split or parallelized. Output includes an estimate of minutes wasted per month.

### gh-pulse

Engineering metrics without the surveillance SaaS. PR cycle time, review latency, and bus factor per directory, pulled straight from the GitHub API and rendered as a local HTML report.

### onboarding-doctor

Answers "can a new developer actually run this repo?" Checks the README setup steps against reality: do the commands exist, do the prerequisites match, does the project actually start. Graded A to F.
