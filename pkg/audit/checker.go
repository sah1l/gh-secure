package audit

import "github.com/sah1l/gh-secure/pkg/github"

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityWarning  Severity = "warning"
	SeverityInfo     Severity = "info"
)

type CheckResult struct {
	Name     string   `json:"name"`
	Passed   bool     `json:"passed"`
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
	Fix      string   `json:"fix,omitempty"`
}

type AuditReport struct {
	Repo    string        `json:"repo"`
	Passed  int           `json:"passed"`
	Total   int           `json:"total"`
	Score   string        `json:"score"`
	Checks  []CheckResult `json:"checks"`
}

func RunAudit(
	settings *github.RepoSettings,
	bp *github.BranchProtection,
	rulesets []github.Ruleset,
	security *github.SecuritySettings,
	files map[string]bool,
) *AuditReport {
	var checks []CheckResult

	// 1. License exists
	checks = append(checks, CheckResult{
		Name:     "License",
		Passed:   settings.License != nil,
		Severity: SeverityWarning,
		Message:  msg(settings.License != nil, "License detected", "No license found"),
		Fix:      "Add a LICENSE file or use `gh secure init` to set one up",
	})

	// 2. Default branch protected
	branchProtected := bp != nil || len(rulesets) > 0
	checks = append(checks, CheckResult{
		Name:     "Branch protection",
		Passed:   branchProtected,
		Severity: SeverityCritical,
		Message:  msg(branchProtected, "Default branch is protected", "Default branch has no protection"),
		Fix:      "Run `gh secure init` to configure branch protection",
	})

	// 3. Require reviews
	hasReviews := (bp != nil && bp.RequiredReviews > 0) || hasReviewRuleset(rulesets)
	checks = append(checks, CheckResult{
		Name:     "Required reviews",
		Passed:   hasReviews,
		Severity: SeverityCritical,
		Message:  msg(hasReviews, "Pull request reviews are required", "No review requirements configured"),
		Fix:      "Run `gh secure init` to require PR reviews",
	})

	// 4. Force push blocked
	forcePushBlocked := (bp != nil && !bp.AllowForcePushes) || hasForcePushRule(rulesets)
	checks = append(checks, CheckResult{
		Name:     "Force push blocked",
		Passed:   forcePushBlocked,
		Severity: SeverityCritical,
		Message:  msg(forcePushBlocked, "Force pushes are blocked", "Force pushes are allowed on default branch"),
		Fix:      "Run `gh secure init` to block force pushes",
	})

	// 5. Branch deletion blocked
	deletionBlocked := (bp != nil && !bp.AllowDeletions) || hasDeletionRule(rulesets)
	checks = append(checks, CheckResult{
		Name:     "Branch deletion blocked",
		Passed:   deletionBlocked,
		Severity: SeverityWarning,
		Message:  msg(deletionBlocked, "Branch deletion is blocked", "Default branch can be deleted"),
		Fix:      "Run `gh secure init` to prevent branch deletion",
	})

	// 6. Delete branch on merge
	checks = append(checks, CheckResult{
		Name:     "Delete branch on merge",
		Passed:   settings.DeleteBranchOnMerge,
		Severity: SeverityInfo,
		Message:  msg(settings.DeleteBranchOnMerge, "Branches are auto-deleted after merge", "Stale branches are not auto-deleted"),
		Fix:      "Run `gh secure init` to enable auto-delete on merge",
	})

	// 7. Vulnerability alerts
	vulnAlerts := security != nil && security.VulnerabilityAlerts
	checks = append(checks, CheckResult{
		Name:     "Vulnerability alerts",
		Passed:   vulnAlerts,
		Severity: SeverityWarning,
		Message:  msg(vulnAlerts, "Vulnerability alerts are enabled", "Vulnerability alerts are disabled"),
		Fix:      "Run `gh secure init` to enable vulnerability alerts",
	})

	// 8. Automated security fixes
	autoFix := security != nil && security.AutomatedSecurityFixes
	checks = append(checks, CheckResult{
		Name:     "Automated security fixes",
		Passed:   autoFix,
		Severity: SeverityInfo,
		Message:  msg(autoFix, "Automated security fixes are enabled", "Automated security fixes are disabled"),
		Fix:      "Run `gh secure init` to enable automated security fixes",
	})

	// 9. Secret scanning
	secretScan := security != nil && security.SecretScanning
	checks = append(checks, CheckResult{
		Name:     "Secret scanning",
		Passed:   secretScan,
		Severity: SeverityWarning,
		Message:  msg(secretScan, "Secret scanning is enabled", "Secret scanning is disabled"),
		Fix:      "Run `gh secure init` to enable secret scanning",
	})

	// 10. SECURITY.md
	hasSecurity := files["SECURITY.md"]
	checks = append(checks, CheckResult{
		Name:     "Security policy",
		Passed:   hasSecurity,
		Severity: SeverityInfo,
		Message:  msg(hasSecurity, "SECURITY.md is present", "No SECURITY.md file"),
		Fix:      "Run `gh secure init` to create a security policy",
	})

	// 11. Dependabot config
	hasDependabot := files[".github/dependabot.yml"]
	checks = append(checks, CheckResult{
		Name:     "Dependabot config",
		Passed:   hasDependabot,
		Severity: SeverityInfo,
		Message:  msg(hasDependabot, "Dependabot is configured", "No dependabot.yml found"),
		Fix:      "Run `gh secure init` to set up Dependabot",
	})

	// 12. Single merge strategy
	mergeCount := 0
	if settings.AllowSquashMerge {
		mergeCount++
	}
	if settings.AllowMergeCommit {
		mergeCount++
	}
	if settings.AllowRebaseMerge {
		mergeCount++
	}
	singleMerge := mergeCount == 1
	checks = append(checks, CheckResult{
		Name:     "Single merge strategy",
		Passed:   singleMerge,
		Severity: SeverityInfo,
		Message:  msg(singleMerge, "Single merge strategy enforced", "Multiple merge strategies allowed"),
		Fix:      "Run `gh secure init` to enforce a single merge strategy",
	})

	passed := 0
	for _, c := range checks {
		if c.Passed {
			passed++
		}
	}

	return &AuditReport{
		Passed: passed,
		Total:  len(checks),
		Score:  scoreLabel(passed, len(checks)),
		Checks: checks,
	}
}

func msg(ok bool, pass, fail string) string {
	if ok {
		return pass
	}
	return fail
}

func scoreLabel(passed, total int) string {
	pct := float64(passed) / float64(total) * 100
	switch {
	case pct >= 90:
		return "A"
	case pct >= 75:
		return "B"
	case pct >= 60:
		return "C"
	case pct >= 40:
		return "D"
	default:
		return "F"
	}
}

func hasReviewRuleset(rulesets []github.Ruleset) bool {
	for _, rs := range rulesets {
		if rs.Enforcement == "disabled" {
			continue
		}
		for _, r := range rs.Rules {
			if r.Type == "pull_request" {
				return true
			}
		}
	}
	return false
}

func hasForcePushRule(rulesets []github.Ruleset) bool {
	for _, rs := range rulesets {
		if rs.Enforcement == "disabled" {
			continue
		}
		for _, r := range rs.Rules {
			if r.Type == "non_fast_forward" {
				return true
			}
		}
	}
	return false
}

func hasDeletionRule(rulesets []github.Ruleset) bool {
	for _, rs := range rulesets {
		if rs.Enforcement == "disabled" {
			continue
		}
		for _, r := range rs.Rules {
			if r.Type == "deletion" {
				return true
			}
		}
	}
	return false
}
