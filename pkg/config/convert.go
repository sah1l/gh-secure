package config

import (
	"strings"

	gh "github.com/sah1l/gh-secure/pkg/github"
)

// StateToConfig converts live repo state into a portable Config.
func StateToConfig(state *gh.CurrentState) *Config {
	cfg := &Config{
		Version:    CurrentVersion,
		Visibility: state.Settings.Visibility,
		MergeStrategy: MergeStrategy{
			AllowSquash: state.Settings.AllowSquashMerge,
			AllowMerge:  state.Settings.AllowMergeCommit,
			AllowRebase: state.Settings.AllowRebaseMerge,
		},
		DeleteBranchOnMerge: state.Settings.DeleteBranchOnMerge,
		Security: SecurityConfig{
			VulnerabilityAlerts:    state.Security.VulnerabilityAlerts,
			AutomatedSecurityFixes: state.Security.AutomatedSecurityFixes,
			SecretScanning:         state.Security.SecretScanning,
			SecretScanningPushProt: state.Security.SecretScanningPushProt,
			DependabotConfig:       state.Files[".github/dependabot.yml"],
		},
	}

	if state.Settings.License != nil {
		cfg.License = state.Settings.License.Key
	}

	// Convert rulesets
	if len(state.Rulesets) > 0 {
		for _, rs := range state.Rulesets {
			rsCfg := rulesetToConfig(rs, state.Settings.DefaultBranch)
			cfg.Rulesets = append(cfg.Rulesets, rsCfg)
		}
	} else if state.Protection != nil {
		cfg.BranchProtection = protectionToConfig(state.Protection)
	}

	// Community files
	for _, path := range []string{"CONTRIBUTING.md", "SECURITY.md", "CODE_OF_CONDUCT.md"} {
		if state.Files[path] {
			cfg.Files = append(cfg.Files, path)
		}
	}
	if state.Files["CODEOWNERS"] || state.Files[".github/CODEOWNERS"] {
		cfg.Files = append(cfg.Files, "CODEOWNERS")
	}

	return cfg
}

func rulesetToConfig(rs gh.Ruleset, defaultBranch string) RulesetConfig {
	rc := RulesetConfig{
		Name:        rs.Name,
		Target:      rs.Target,
		Enforcement: rs.Enforcement,
	}

	// Convert conditions to branch list
	for _, ref := range rs.Conditions.RefName.Include {
		branch := strings.TrimPrefix(ref, "refs/heads/")
		if branch == defaultBranch {
			branch = "~DEFAULT_BRANCH~"
		}
		rc.Branches = append(rc.Branches, branch)
	}

	// Check bypass actors for admin bypass
	for _, actor := range rs.BypassActors {
		if actor.ActorType == "RepositoryRole" && actor.ActorID == 5 {
			rc.AdminBypass = true
			break
		}
	}

	// Parse rules
	for _, rule := range rs.Rules {
		switch rule.Type {
		case "pull_request":
			if rule.Parameters != nil {
				rc.RequiredReviews = rule.Parameters.RequiredApprovingReviewCount
				rc.DismissStaleReviews = rule.Parameters.DismissStaleReviewsOnPush
				rc.RequireCodeOwners = rule.Parameters.RequireCodeOwnerReview
				rc.AllowedMergeMethods = rule.Parameters.AllowedMergeMethods
			}
		case "required_linear_history":
			rc.RequireLinearHistory = true
		case "required_signatures":
			rc.RequireSignedCommits = true
		case "deletion":
			rc.PreventDeletion = true
		case "non_fast_forward":
			rc.PreventForcePush = true
		}
	}

	return rc
}

func protectionToConfig(bp *gh.BranchProtection) *BranchProtConfig {
	return &BranchProtConfig{
		RequiredReviews:      bp.RequiredReviews,
		DismissStaleReviews:  bp.DismissStaleReviews,
		RequireCodeOwners:    bp.RequireCodeOwners,
		RequiredStatusChecks: bp.RequiredStatusChecks,
		StrictStatusChecks:   bp.StrictStatusChecks,
		EnforceAdmins:        bp.EnforceAdmins,
		AllowForcePushes:     bp.AllowForcePushes,
		AllowDeletions:       bp.AllowDeletions,
		RequireLinearHistory: bp.RequireLinearHistory,
		RequireSignedCommits: bp.RequireSignedCommits,
	}
}
