package config

var Presets = map[string]Config{
	"oss": {
		Version:    1,
		Visibility: "public",
		License:    "mit",
		MergeStrategy: MergeStrategy{
			AllowSquash: true,
			AllowMerge:  false,
			AllowRebase: false,
		},
		DeleteBranchOnMerge: true,
		Rulesets: []RulesetConfig{
			{
				Name:                "Protect main",
				Target:              "branch",
				Enforcement:         "active",
				Branches:            []string{"main"},
				RequiredReviews:     1,
				DismissStaleReviews: true,
				PreventDeletion:     true,
				PreventForcePush:    true,
				AllowedMergeMethods: []string{"squash"},
				AdminBypass:         true,
			},
		},
		Security: SecurityConfig{
			VulnerabilityAlerts:    true,
			AutomatedSecurityFixes: true,
			SecretScanning:         true,
			SecretScanningPushProt: true,
			DependabotConfig:       true,
		},
		Files: []string{"CONTRIBUTING.md", "SECURITY.md", "CODE_OF_CONDUCT.md", "CODEOWNERS"},
	},

	"private": {
		Version:    1,
		Visibility: "private",
		MergeStrategy: MergeStrategy{
			AllowSquash: true,
			AllowMerge:  false,
			AllowRebase: false,
		},
		DeleteBranchOnMerge: true,
		Rulesets: []RulesetConfig{
			{
				Name:                "Protect main",
				Target:              "branch",
				Enforcement:         "active",
				Branches:            []string{"main"},
				RequiredReviews:     2,
				DismissStaleReviews: true,
				PreventDeletion:     true,
				PreventForcePush:    true,
				AllowedMergeMethods: []string{"squash"},
				AdminBypass:         true,
			},
		},
		Security: SecurityConfig{
			VulnerabilityAlerts:    true,
			AutomatedSecurityFixes: true,
			SecretScanning:         false,
			SecretScanningPushProt: false,
			DependabotConfig:       true,
		},
	},

	"strict": {
		Version:    1,
		Visibility: "private",
		MergeStrategy: MergeStrategy{
			AllowSquash: true,
			AllowMerge:  false,
			AllowRebase: false,
		},
		DeleteBranchOnMerge: true,
		Rulesets: []RulesetConfig{
			{
				Name:                 "Protect main",
				Target:               "branch",
				Enforcement:          "active",
				Branches:             []string{"main"},
				RequiredReviews:      2,
				DismissStaleReviews:  true,
				RequireCodeOwners:    true,
				RequireLinearHistory: true,
				RequireSignedCommits: true,
				PreventDeletion:      true,
				PreventForcePush:     true,
				AllowedMergeMethods:  []string{"squash"},
			},
		},
		Security: SecurityConfig{
			VulnerabilityAlerts:    true,
			AutomatedSecurityFixes: true,
			SecretScanning:         true,
			SecretScanningPushProt: true,
			DependabotConfig:       true,
		},
	},
}

func PresetNames() []string {
	return []string{"oss", "private", "strict"}
}

func GetPreset(name string) (Config, bool) {
	cfg, ok := Presets[name]
	return cfg, ok
}
