package audit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	gh "github.com/sah1l/gh-secure/pkg/github"
)

func TestRunAudit(t *testing.T) {
	t.Run("all checks pass", func(t *testing.T) {
		settings := &gh.RepoSettings{
			License:             &gh.License{Key: "mit"},
			DeleteBranchOnMerge: true,
			AllowSquashMerge:    true,
			AllowMergeCommit:    false,
			AllowRebaseMerge:    false,
		}
		rulesets := []gh.Ruleset{
			{
				Name:        "Protect main",
				Enforcement: "active",
				Rules: []gh.Rule{
					{Type: "pull_request", Parameters: &gh.RuleParameters{RequiredApprovingReviewCount: 1}},
					{Type: "deletion"},
					{Type: "non_fast_forward"},
				},
			},
		}
		security := &gh.SecuritySettings{
			VulnerabilityAlerts:    true,
			AutomatedSecurityFixes: true,
			SecretScanning:         true,
		}
		files := map[string]bool{
			"SECURITY.md":           true,
			".github/dependabot.yml": true,
		}

		report := RunAudit(settings, nil, rulesets, security, files)

		assert.Equal(t, 12, report.Total)
		assert.Equal(t, 12, report.Passed)
		assert.Equal(t, "A", report.Score)
	})

	t.Run("all checks fail", func(t *testing.T) {
		settings := &gh.RepoSettings{}
		rulesets := []gh.Ruleset{}
		security := &gh.SecuritySettings{}
		files := map[string]bool{}

		report := RunAudit(settings, nil, rulesets, security, files)

		assert.Equal(t, 12, report.Total)
		assert.Equal(t, 0, report.Passed)
		assert.Equal(t, "F", report.Score)
	})

	t.Run("mixed results", func(t *testing.T) {
		settings := &gh.RepoSettings{
			License:             &gh.License{Key: "mit"},
			DeleteBranchOnMerge: false,
			AllowSquashMerge:    true,
			AllowMergeCommit:    true,
			AllowRebaseMerge:    true,
		}
		security := &gh.SecuritySettings{
			VulnerabilityAlerts:    false,
			AutomatedSecurityFixes: false,
			SecretScanning:         false,
		}
		files := map[string]bool{}

		report := RunAudit(settings, nil, nil, security, files)

		// Only License passes (1 out of 12)
		// All other checks fail: no branch protection, no security features, no community files, multiple merge strategies
		assert.Equal(t, 12, report.Total)
		assert.Equal(t, 1, report.Passed) // License only
		assert.Equal(t, "F", report.Score)
	})

	t.Run("with branch protection", func(t *testing.T) {
		settings := &gh.RepoSettings{
			DeleteBranchOnMerge: true,
			AllowSquashMerge:    true,
		}
		bp := &gh.BranchProtection{
			RequiredReviews:  1,
			AllowForcePushes:  false,
			AllowDeletions:    false,
		}
		security := &gh.SecuritySettings{}
		files := map[string]bool{}

		report := RunAudit(settings, bp, nil, security, files)

		// Check that branch protection is detected
		assert.True(t, report.Checks[1].Passed) // Branch protection
		assert.True(t, report.Checks[2].Passed) // Required reviews
		assert.True(t, report.Checks[3].Passed) // Force push blocked
		assert.True(t, report.Checks[4].Passed) // Branch deletion blocked
	})
}

func TestScoreLabel(t *testing.T) {
	tests := []struct {
		passed  int
		total   int
		want    string
	}{
		{12, 12, "A"},  // 100%
		{11, 12, "A"},  // 91.67%
		{10, 12, "B"},  // 83.33%
		{9, 12, "B"},   // 75%
		{8, 12, "C"},   // 66.67%
		{7, 12, "D"},   // 58.33% - below 60% threshold
		{5, 12, "D"},   // 41.67%
		{4, 12, "F"},   // 33.33% - below 40% threshold
		{3, 12, "F"},   // 25%
		{0, 12, "F"},   // 0%
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			got := scoreLabel(tt.passed, tt.total)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestHasActiveRulesets(t *testing.T) {
	t.Run("active rulesets", func(t *testing.T) {
		rulesets := []gh.Ruleset{
			{Enforcement: "active"},
			{Enforcement: "active"},
		}
		assert.True(t, hasActiveRulesets(rulesets))
	})

	t.Run("disabled rulesets only", func(t *testing.T) {
		rulesets := []gh.Ruleset{
			{Enforcement: "disabled"},
			{Enforcement: "disabled"},
		}
		assert.False(t, hasActiveRulesets(rulesets))
	})

	t.Run("mixed", func(t *testing.T) {
		rulesets := []gh.Ruleset{
			{Enforcement: "disabled"},
			{Enforcement: "active"},
		}
		assert.True(t, hasActiveRulesets(rulesets))
	})

	t.Run("empty", func(t *testing.T) {
		assert.False(t, hasActiveRulesets(nil))
		assert.False(t, hasActiveRulesets([]gh.Ruleset{}))
	})
}

func TestHasReviewRuleset(t *testing.T) {
	t.Run("active with pull_request rule", func(t *testing.T) {
		rulesets := []gh.Ruleset{
			{
				Enforcement: "active",
				Rules:       []gh.Rule{{Type: "pull_request"}},
			},
		}
		assert.True(t, hasReviewRuleset(rulesets))
	})

	t.Run("disabled ruleset", func(t *testing.T) {
		rulesets := []gh.Ruleset{
			{
				Enforcement: "disabled",
				Rules:       []gh.Rule{{Type: "pull_request"}},
			},
		}
		assert.False(t, hasReviewRuleset(rulesets))
	})

	t.Run("no pull_request rule", func(t *testing.T) {
		rulesets := []gh.Ruleset{
			{
				Enforcement: "active",
				Rules:       []gh.Rule{{Type: "deletion"}},
			},
		}
		assert.False(t, hasReviewRuleset(rulesets))
	})

	t.Run("empty", func(t *testing.T) {
		assert.False(t, hasReviewRuleset(nil))
	})
}

func TestHasForcePushRule(t *testing.T) {
	t.Run("active with non_fast_forward rule", func(t *testing.T) {
		rulesets := []gh.Ruleset{
			{
				Enforcement: "active",
				Rules:       []gh.Rule{{Type: "non_fast_forward"}},
			},
		}
		assert.True(t, hasForcePushRule(rulesets))
	})

	t.Run("disabled ruleset", func(t *testing.T) {
		rulesets := []gh.Ruleset{
			{
				Enforcement: "disabled",
				Rules:       []gh.Rule{{Type: "non_fast_forward"}},
			},
		}
		assert.False(t, hasForcePushRule(rulesets))
	})

	t.Run("empty", func(t *testing.T) {
		assert.False(t, hasForcePushRule(nil))
	})
}

func TestHasDeletionRule(t *testing.T) {
	t.Run("active with deletion rule", func(t *testing.T) {
		rulesets := []gh.Ruleset{
			{
				Enforcement: "active",
				Rules:       []gh.Rule{{Type: "deletion"}},
			},
		}
		assert.True(t, hasDeletionRule(rulesets))
	})

	t.Run("disabled ruleset", func(t *testing.T) {
		rulesets := []gh.Ruleset{
			{
				Enforcement: "disabled",
				Rules:       []gh.Rule{{Type: "deletion"}},
			},
		}
		assert.False(t, hasDeletionRule(rulesets))
	})

	t.Run("empty", func(t *testing.T) {
		assert.False(t, hasDeletionRule(nil))
	})
}
