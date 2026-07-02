package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gh "github.com/sah1l/gh-secure/pkg/github"
)

func TestMarshal(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *Config
		wantErr bool
	}{
		{
			name: "full config",
			cfg: &Config{
				Version:    1,
				Visibility: "public",
				MergeStrategy: MergeStrategy{
					AllowSquash: true,
					AllowMerge:  false,
					AllowRebase: false,
				},
				DeleteBranchOnMerge: true,
				Security: SecurityConfig{
					VulnerabilityAlerts:    true,
					AutomatedSecurityFixes: true,
					SecretScanning:         true,
				},
			},
			wantErr: false,
		},
		{
			name: "empty config",
			cfg: &Config{
				MergeStrategy: MergeStrategy{},
				Security:      SecurityConfig{},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := Marshal(tt.cfg)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.NotEmpty(t, data)
			// Verify version is set
			assert.Contains(t, string(data), "version: 1")
		})
	}
}

func TestUnmarshal(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		wantErr bool
		check   func(*testing.T, *Config)
	}{
		{
			name: "full config",
			data: `version: 1
visibility: public
license: mit
merge_strategy:
  allow_squash: true
  allow_merge: false
delete_branch_on_merge: true
security:
  vulnerability_alerts: true
  secret_scanning: true
`,
			wantErr: false,
			check: func(t *testing.T, cfg *Config) {
				assert.Equal(t, 1, cfg.Version)
				assert.Equal(t, "public", cfg.Visibility)
				assert.Equal(t, "mit", cfg.License)
				assert.True(t, cfg.MergeStrategy.AllowSquash)
				assert.True(t, cfg.DeleteBranchOnMerge)
				assert.True(t, cfg.Security.VulnerabilityAlerts)
				assert.True(t, cfg.Security.SecretScanning)
			},
		},
		{
			name:    "empty data",
			data:    "",
			wantErr: false,
			check: func(t *testing.T, cfg *Config) {
				// Version should default to CurrentVersion
				assert.Equal(t, CurrentVersion, cfg.Version)
			},
		},
		{
			name:    "invalid yaml",
			data:    "invalid: yaml: content: [",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := Unmarshal([]byte(tt.data))
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			tt.check(t, cfg)
		})
	}
}

func TestMarshalUnmarshalRoundTrip(t *testing.T) {
	original := &Config{
		Version:             1,
		Visibility:         "private",
		License:            "mit",
		DeleteBranchOnMerge: true,
		MergeStrategy: MergeStrategy{
			AllowSquash: true,
			AllowMerge:  false,
			AllowRebase: false,
		},
		Security: SecurityConfig{
			VulnerabilityAlerts:    true,
			AutomatedSecurityFixes: true,
			SecretScanning:         true,
			SecretScanningPushProt: true,
			DependabotConfig:       true,
		},
		Rulesets: []RulesetConfig{
			{
				Name:                 "Protect main",
				Target:               "branch",
				Enforcement:          "active",
				Branches:             []string{"main"},
				RequiredReviews:      2,
				DismissStaleReviews:  true,
				RequireCodeOwners:    true,
				PreventDeletion:      true,
				PreventForcePush:     true,
				AllowedMergeMethods:  []string{"squash"},
			},
		},
		Files: []string{"CONTRIBUTING.md", "SECURITY.md"},
	}

	data, err := Marshal(original)
	require.NoError(t, err)

	decoded, err := Unmarshal(data)
	require.NoError(t, err)

	assert.Equal(t, original.Version, decoded.Version)
	assert.Equal(t, original.Visibility, decoded.Visibility)
	assert.Equal(t, original.License, decoded.License)
	assert.Equal(t, original.MergeStrategy, decoded.MergeStrategy)
	assert.Equal(t, original.DeleteBranchOnMerge, decoded.DeleteBranchOnMerge)
	assert.Equal(t, original.Security, decoded.Security)
	assert.Equal(t, len(original.Rulesets), len(decoded.Rulesets))
	assert.Equal(t, original.Files, decoded.Files)
}

func TestGetPreset(t *testing.T) {
	tests := []struct {
		name      string
		preset    string
		wantFound bool
		check     func(*testing.T, Config)
	}{
		{
			name:      "oss preset",
			preset:    "oss",
			wantFound: true,
			check: func(t *testing.T, cfg Config) {
				assert.Equal(t, "public", cfg.Visibility)
				assert.Equal(t, "mit", cfg.License)
				assert.Equal(t, 1, cfg.Rulesets[0].RequiredReviews)
			},
		},
		{
			name:      "private preset",
			preset:    "private",
			wantFound: true,
			check: func(t *testing.T, cfg Config) {
				assert.Equal(t, "private", cfg.Visibility)
				assert.Equal(t, 2, cfg.Rulesets[0].RequiredReviews)
				assert.False(t, cfg.Security.SecretScanning)
			},
		},
		{
			name:      "strict preset",
			preset:    "strict",
			wantFound: true,
			check: func(t *testing.T, cfg Config) {
				assert.Equal(t, "private", cfg.Visibility)
				assert.True(t, cfg.Rulesets[0].RequireCodeOwners)
				assert.True(t, cfg.Rulesets[0].RequireLinearHistory)
				assert.True(t, cfg.Rulesets[0].RequireSignedCommits)
			},
		},
		{
			name:      "invalid preset",
			preset:    "invalid",
			wantFound: false,
			check: func(t *testing.T, cfg Config) {
				assert.Zero(t, cfg.Version)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, found := GetPreset(tt.preset)
			assert.Equal(t, tt.wantFound, found)
			tt.check(t, cfg)
		})
	}
}

func TestPresetNames(t *testing.T) {
	names := PresetNames()
	assert.ElementsMatch(t, []string{"oss", "private", "strict"}, names)
}

func TestStateToConfig(t *testing.T) {
	t.Run("empty state", func(t *testing.T) {
		state := &gh.CurrentState{}
		cfg := StateToConfig(state)
		assert.NotNil(t, cfg)
		assert.Equal(t, CurrentVersion, cfg.Version)
	})

	t.Run("with settings and security", func(t *testing.T) {
		state := &gh.CurrentState{
			Settings: &gh.RepoSettings{
				Visibility:         "public",
				DefaultBranch:       "main",
				AllowSquashMerge:   true,
				AllowMergeCommit:   false,
				AllowRebaseMerge:   false,
				DeleteBranchOnMerge: true,
				License: &gh.License{
					Key: "mit",
				},
			},
			Security: &gh.SecuritySettings{
				VulnerabilityAlerts:    true,
				AutomatedSecurityFixes: true,
				SecretScanning:         true,
				SecretScanningPushProt: true,
			},
			Files: map[string]bool{
				"SECURITY.md":       true,
				"CONTRIBUTING.md":   true,
				".github/dependabot.yml": true,
			},
		}

		cfg := StateToConfig(state)

		assert.Equal(t, "public", cfg.Visibility)
		assert.Equal(t, "mit", cfg.License)
		assert.True(t, cfg.MergeStrategy.AllowSquash)
		assert.True(t, cfg.DeleteBranchOnMerge)
		assert.True(t, cfg.Security.VulnerabilityAlerts)
		assert.True(t, cfg.Security.DependabotConfig)
		assert.Contains(t, cfg.Files, "SECURITY.md")
		assert.Contains(t, cfg.Files, "CONTRIBUTING.md")
	})

	t.Run("with rulesets", func(t *testing.T) {
		state := &gh.CurrentState{
			Settings: &gh.RepoSettings{
				DefaultBranch: "main",
			},
			Rulesets: []gh.Ruleset{
				{
					Name:        "Protect main",
					Target:      "branch",
					Enforcement: "active",
					Conditions: gh.RulesetConditions{
						RefName: struct {
							Include []string `json:"include"`
							Exclude []string `json:"exclude"`
						}{
							Include: []string{"refs/heads/main"},
						},
					},
					Rules: []gh.Rule{
						{
							Type: "pull_request",
							Parameters: &gh.RuleParameters{
								RequiredApprovingReviewCount: 2,
								DismissStaleReviewsOnPush:   true,
							},
						},
						{Type: "deletion"},
						{Type: "non_fast_forward"},
					},
				},
			},
		}

		cfg := StateToConfig(state)

		require.Len(t, cfg.Rulesets, 1)
		assert.Equal(t, "Protect main", cfg.Rulesets[0].Name)
		assert.Equal(t, 2, cfg.Rulesets[0].RequiredReviews)
		assert.True(t, cfg.Rulesets[0].PreventDeletion)
		assert.True(t, cfg.Rulesets[0].PreventForcePush)
	})

	t.Run("with branch protection (fallback)", func(t *testing.T) {
		state := &gh.CurrentState{
			Settings: &gh.RepoSettings{
				DefaultBranch: "main",
			},
			Protection: &gh.BranchProtection{
				RequiredReviews:     1,
				DismissStaleReviews: true,
				RequireCodeOwners:   true,
				EnforceAdmins:       true,
				AllowForcePushes:    false,
				AllowDeletions:      false,
			},
		}

		cfg := StateToConfig(state)

		assert.NotNil(t, cfg.BranchProtection)
		assert.Equal(t, 1, cfg.BranchProtection.RequiredReviews)
		assert.True(t, cfg.BranchProtection.RequireCodeOwners)
		assert.False(t, cfg.BranchProtection.AllowForcePushes)
		assert.False(t, cfg.BranchProtection.AllowDeletions)
	})
}

func TestRulesetToConfig(t *testing.T) {
	t.Run("default branch substitution", func(t *testing.T) {
		rs := gh.Ruleset{
			Name:        "Protect",
			Target:      "branch",
			Enforcement: "active",
			Conditions: gh.RulesetConditions{
				RefName: struct {
					Include []string `json:"include"`
					Exclude []string `json:"exclude"`
				}{
					Include: []string{"refs/heads/main"},
				},
			},
			Rules: []gh.Rule{
				{Type: "pull_request"},
			},
		}

		rc := rulesetToConfig(rs, "main")
		assert.Equal(t, []string{"~DEFAULT_BRANCH~"}, rc.Branches)
	})

	t.Run("non-default branch kept as-is", func(t *testing.T) {
		rs := gh.Ruleset{
			Name:        "Protect",
			Target:      "branch",
			Enforcement: "active",
			Conditions: gh.RulesetConditions{
				RefName: struct {
					Include []string `json:"include"`
					Exclude []string `json:"exclude"`
				}{
					Include: []string{"refs/heads/develop"},
				},
			},
			Rules: []gh.Rule{},
		}

		rc := rulesetToConfig(rs, "main")
		assert.Equal(t, []string{"develop"}, rc.Branches)
	})

	t.Run("admin bypass detection", func(t *testing.T) {
		rs := gh.Ruleset{
			Name:        "Protect",
			Target:      "branch",
			Enforcement: "active",
			Conditions: gh.RulesetConditions{
				RefName: struct {
					Include []string `json:"include"`
					Exclude []string `json:"exclude"`
				}{
					Include: []string{"refs/heads/main"},
				},
			},
			BypassActors: []gh.BypassActor{
				{ActorID: 5, ActorType: "RepositoryRole"},
			},
			Rules: []gh.Rule{},
		}

		rc := rulesetToConfig(rs, "main")
		assert.True(t, rc.AdminBypass)
	})
}

func TestProtectionToConfig(t *testing.T) {
	bp := &gh.BranchProtection{
		RequiredReviews:      2,
		DismissStaleReviews:  true,
		RequireCodeOwners:    true,
		RequiredStatusChecks: []string{"test", "lint"},
		StrictStatusChecks:   true,
		EnforceAdmins:        true,
		AllowForcePushes:     false,
		AllowDeletions:       false,
		RequireLinearHistory: true,
		RequireSignedCommits: true,
	}

	cfg := protectionToConfig(bp)

	assert.Equal(t, 2, cfg.RequiredReviews)
	assert.True(t, cfg.DismissStaleReviews)
	assert.True(t, cfg.RequireCodeOwners)
	assert.Equal(t, []string{"test", "lint"}, cfg.RequiredStatusChecks)
	assert.True(t, cfg.StrictStatusChecks)
	assert.True(t, cfg.EnforceAdmins)
	assert.False(t, cfg.AllowForcePushes)
	assert.False(t, cfg.AllowDeletions)
	assert.True(t, cfg.RequireLinearHistory)
	assert.True(t, cfg.RequireSignedCommits)
}
