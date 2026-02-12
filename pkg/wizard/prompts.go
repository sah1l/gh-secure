package wizard

import (
	"github.com/charmbracelet/huh"
	"github.com/sahilxyz/gh-secure/pkg/config"
	gh "github.com/sahilxyz/gh-secure/pkg/github"
)

type Answers struct {
	Visibility           string
	License              string
	MergeSquash          bool
	MergeMerge           bool
	MergeRebase          bool
	DeleteBranchOnMerge  bool
	RequiredReviews      int
	DismissStaleReviews  bool
	RequireCodeOwners    bool
	AdminBypass          bool
	RequireLinearHistory bool
	RequireSignedCommits bool
	VulnAlerts           bool
	AutoSecurityFixes    bool
	SecretScanning       bool
	SecretScanPushProt   bool
	DependabotConfig     bool
	CommunityFiles       []string
}

func reviewOptions() []huh.Option[int] {
	return []huh.Option[int]{
		huh.NewOption("None", 0),
		huh.NewOption("1 reviewer", 1),
		huh.NewOption("2 reviewers", 2),
		huh.NewOption("3 reviewers", 3),
	}
}

func RunWizard(current *gh.CurrentState) (*config.Config, error) {
	var a Answers

	// Default defaults (used when current is nil)
	a.MergeSquash = true
	a.DeleteBranchOnMerge = true
	a.RequiredReviews = 1
	a.DismissStaleReviews = true
	a.VulnAlerts = true
	a.AutoSecurityFixes = true

	if current != nil {
		// Pre-populate from current repo state
		if current.Settings != nil {
			a.Visibility = current.Settings.Visibility
			a.MergeSquash = current.Settings.AllowSquashMerge
			a.MergeMerge = current.Settings.AllowMergeCommit
			a.MergeRebase = current.Settings.AllowRebaseMerge
			a.DeleteBranchOnMerge = current.Settings.DeleteBranchOnMerge
			// Pre-populate license from current repo
			if current.Settings.License != nil {
				a.License = current.Settings.License.Key
			}
		}
		if current.Security != nil {
			a.VulnAlerts = current.Security.VulnerabilityAlerts
			a.AutoSecurityFixes = current.Security.AutomatedSecurityFixes
			a.SecretScanning = current.Security.SecretScanning
			a.SecretScanPushProt = current.Security.SecretScanningPushProt
		}
		// Pre-populate dependabot: keep enabled if already exists, suggest creating if missing
		a.DependabotConfig = current.Files[".github/dependabot.yml"]
		if !a.DependabotConfig {
			a.DependabotConfig = true // default to creating if missing
		}

		// Pre-populate branch protection from rulesets or legacy protection
		if len(current.Rulesets) > 0 {
			rs := current.Rulesets[0]
			for _, rule := range rs.Rules {
				switch rule.Type {
				case "pull_request":
					if rule.Parameters != nil {
						a.RequiredReviews = rule.Parameters.RequiredApprovingReviewCount
						a.DismissStaleReviews = rule.Parameters.DismissStaleReviewsOnPush
						a.RequireCodeOwners = rule.Parameters.RequireCodeOwnerReview
					}
				case "required_linear_history":
					a.RequireLinearHistory = true
				case "required_signatures":
					a.RequireSignedCommits = true
				}
			}
			// Check if admin bypass is configured
			for _, actor := range rs.BypassActors {
				if actor.ActorType == "RepositoryRole" && actor.ActorID == 5 {
					a.AdminBypass = true
					break
				}
			}
		} else if current.Protection != nil {
			a.RequiredReviews = current.Protection.RequiredReviews
			a.DismissStaleReviews = current.Protection.DismissStaleReviews
			a.RequireCodeOwners = current.Protection.RequireCodeOwners
			a.AdminBypass = !current.Protection.EnforceAdmins
			a.RequireLinearHistory = current.Protection.RequireLinearHistory
			a.RequireSignedCommits = current.Protection.RequireSignedCommits
		}

		// Pre-select all community files: existing ones stay selected (applyConfig skips them),
		// missing ones are also selected so they get created.
		for _, f := range []string{"CONTRIBUTING.md", "SECURITY.md", "CODE_OF_CONDUCT.md"} {
			a.CommunityFiles = append(a.CommunityFiles, f)
		}
		// Always include CODEOWNERS in the selection
		a.CommunityFiles = append(a.CommunityFiles, "CODEOWNERS")
	}

	// Section 1: Visibility
	visForm := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Repository visibility").
				Options(
					huh.NewOption("Public", "public"),
					huh.NewOption("Private", "private"),
				).
				Value(&a.Visibility),
		),
	)
	if err := visForm.Run(); err != nil {
		return nil, err
	}

	// Section 2: Open Source (only for public repos)
	if a.Visibility == "public" {
		ossForm := huh.NewForm(
			huh.NewGroup(
				huh.NewSelect[string]().
					Title("License").
					Options(
						huh.NewOption("MIT", "mit"),
						huh.NewOption("Apache 2.0", "apache-2.0"),
						huh.NewOption("GPL 3.0", "gpl-3.0"),
						huh.NewOption("None", ""),
					).
					Value(&a.License),
				huh.NewMultiSelect[string]().
					Title("Community files to create").
					Options(
						huh.NewOption("CONTRIBUTING.md", "CONTRIBUTING.md"),
						huh.NewOption("SECURITY.md", "SECURITY.md"),
						huh.NewOption("CODE_OF_CONDUCT.md", "CODE_OF_CONDUCT.md"),
						huh.NewOption("CODEOWNERS", "CODEOWNERS"),
					).
					Value(&a.CommunityFiles),
			),
		)
		if err := ossForm.Run(); err != nil {
			return nil, err
		}
	}

	// Section 3: Merge Strategy
	mergeForm := huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().
				Title("Allow squash merge?").
				Value(&a.MergeSquash),
			huh.NewConfirm().
				Title("Allow merge commit?").
				Value(&a.MergeMerge),
			huh.NewConfirm().
				Title("Allow rebase merge?").
				Value(&a.MergeRebase),
			huh.NewConfirm().
				Title("Delete branch on merge?").
				Value(&a.DeleteBranchOnMerge),
		),
	)
	if err := mergeForm.Run(); err != nil {
		return nil, err
	}

	// Section 4: Branch Protection
	protForm := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[int]().
				Title("Required PR reviews").
				Options(reviewOptions()...).
				Value(&a.RequiredReviews),
			huh.NewConfirm().
				Title("Dismiss stale reviews?").
				Value(&a.DismissStaleReviews),
			huh.NewConfirm().
				Title("Require CODEOWNERS review?").
				Value(&a.RequireCodeOwners),
			huh.NewConfirm().
				Title("Allow repo admin to bypass rules?").
				Value(&a.AdminBypass),
			huh.NewConfirm().
				Title("Require linear history?").
				Value(&a.RequireLinearHistory),
			huh.NewConfirm().
				Title("Require signed commits?").
				Value(&a.RequireSignedCommits),
		),
	)
	if err := protForm.Run(); err != nil {
		return nil, err
	}

	// Section 5: Security
	secForm := huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().
				Title("Enable vulnerability alerts?").
				Value(&a.VulnAlerts),
			huh.NewConfirm().
				Title("Enable automated security fixes?").
				Value(&a.AutoSecurityFixes),
			huh.NewConfirm().
				Title("Enable secret scanning?").
				Value(&a.SecretScanning),
			huh.NewConfirm().
				Title("Enable secret scanning push protection?").
				Value(&a.SecretScanPushProt),
			huh.NewConfirm().
				Title("Create dependabot.yml?").
				Value(&a.DependabotConfig),
		),
	)
	if err := secForm.Run(); err != nil {
		return nil, err
	}

	return answersToConfig(&a), nil
}

func answersToConfig(a *Answers) *config.Config {
	cfg := &config.Config{
		Version:    1,
		Visibility: a.Visibility,
		License:    a.License,
		MergeStrategy: config.MergeStrategy{
			AllowSquash: a.MergeSquash,
			AllowMerge:  a.MergeMerge,
			AllowRebase: a.MergeRebase,
		},
		DeleteBranchOnMerge: a.DeleteBranchOnMerge,
		Security: config.SecurityConfig{
			VulnerabilityAlerts:    a.VulnAlerts,
			AutomatedSecurityFixes: a.AutoSecurityFixes,
			SecretScanning:         a.SecretScanning,
			SecretScanningPushProt: a.SecretScanPushProt,
			DependabotConfig:       a.DependabotConfig,
		},
		Files: a.CommunityFiles,
	}

	if a.RequiredReviews > 0 || a.RequireLinearHistory || a.RequireSignedCommits {
		// Build allowed merge methods from merge strategy selections
		var methods []string
		if a.MergeSquash {
			methods = append(methods, "squash")
		}
		if a.MergeMerge {
			methods = append(methods, "merge")
		}
		if a.MergeRebase {
			methods = append(methods, "rebase")
		}

		cfg.Rulesets = []config.RulesetConfig{
			{
				Name:                 "Protect default branch",
				Target:               "branch",
				Enforcement:          "active",
				Branches:             []string{"~DEFAULT_BRANCH~"},
				RequiredReviews:      a.RequiredReviews,
				DismissStaleReviews:  a.DismissStaleReviews,
				RequireCodeOwners:    a.RequireCodeOwners,
				RequireLinearHistory: a.RequireLinearHistory,
				RequireSignedCommits: a.RequireSignedCommits,
				PreventDeletion:      true,
				PreventForcePush:     true,
				AllowedMergeMethods:  methods,
				AdminBypass:          a.AdminBypass,
			},
		}
	}

	return cfg
}
