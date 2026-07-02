package wizard

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAnswersToConfig(t *testing.T) {
	t.Run("minimal answers", func(t *testing.T) {
		a := &Answers{
			Visibility:          "public",
			MergeSquash:        true,
			DeleteBranchOnMerge: true,
			RequiredReviews:    1,
			DismissStaleReviews: true,
		}

		cfg := answersToConfig(a)

		assert.NotNil(t, cfg)
		assert.Equal(t, "public", cfg.Visibility)
		assert.True(t, cfg.MergeStrategy.AllowSquash)
		assert.True(t, cfg.DeleteBranchOnMerge)
		assert.Equal(t, 1, cfg.Rulesets[0].RequiredReviews)
		assert.True(t, cfg.Rulesets[0].DismissStaleReviews)
	})

	t.Run("private repo", func(t *testing.T) {
		a := &Answers{
			Visibility:          "private",
			MergeSquash:          true,
			DeleteBranchOnMerge:  true,
			RequiredReviews:      2,
			DismissStaleReviews:  true,
			RequireCodeOwners:   true,
			AdminBypass:          true,
		}

		cfg := answersToConfig(a)

		assert.Equal(t, "private", cfg.Visibility)
		require.Len(t, cfg.Rulesets, 1)
		assert.Equal(t, 2, cfg.Rulesets[0].RequiredReviews)
		assert.True(t, cfg.Rulesets[0].RequireCodeOwners)
		assert.True(t, cfg.Rulesets[0].AdminBypass)
	})

	t.Run("with strict settings", func(t *testing.T) {
		a := &Answers{
			Visibility:           "private",
			MergeSquash:          true,
			DeleteBranchOnMerge:  true,
			RequiredReviews:      2,
			DismissStaleReviews:  true,
			RequireCodeOwners:    true,
			RequireLinearHistory: true,
			RequireSignedCommits: true,
		}

		cfg := answersToConfig(a)

		require.Len(t, cfg.Rulesets, 1)
		assert.True(t, cfg.Rulesets[0].RequireLinearHistory)
		assert.True(t, cfg.Rulesets[0].RequireSignedCommits)
	})

	t.Run("with security settings", func(t *testing.T) {
		a := &Answers{
			Visibility:           "public",
			MergeSquash:          true,
			DeleteBranchOnMerge:  true,
			RequiredReviews:      1,
			VulnAlerts:           true,
			AutoSecurityFixes:   true,
			SecretScanning:       true,
			SecretScanPushProt:  true,
			DependabotConfig:     true,
		}

		cfg := answersToConfig(a)

		assert.True(t, cfg.Security.VulnerabilityAlerts)
		assert.True(t, cfg.Security.AutomatedSecurityFixes)
		assert.True(t, cfg.Security.SecretScanning)
		assert.True(t, cfg.Security.SecretScanningPushProt)
		assert.True(t, cfg.Security.DependabotConfig)
	})

	t.Run("with community files", func(t *testing.T) {
		a := &Answers{
			Visibility:          "public",
			MergeSquash:        true,
			DeleteBranchOnMerge: true,
			RequiredReviews:    1,
			CommunityFiles:     []string{"CONTRIBUTING.md", "SECURITY.md", "CODE_OF_CONDUCT.md", "CODEOWNERS"},
		}

		cfg := answersToConfig(a)

		assert.ElementsMatch(t, []string{"CONTRIBUTING.md", "SECURITY.md", "CODE_OF_CONDUCT.md", "CODEOWNERS"}, cfg.Files)
	})

	t.Run("with license", func(t *testing.T) {
		a := &Answers{
			Visibility:          "public",
			License:             "mit",
			MergeSquash:        true,
			DeleteBranchOnMerge: true,
			RequiredReviews:    1,
		}

		cfg := answersToConfig(a)

		assert.Equal(t, "mit", cfg.License)
	})

	t.Run("all merge strategies disabled", func(t *testing.T) {
		a := &Answers{
			Visibility:          "private",
			MergeSquash:        false,
			MergeMerge:         false,
			MergeRebase:        false,
			DeleteBranchOnMerge: false,
		}

		cfg := answersToConfig(a)

		assert.False(t, cfg.MergeStrategy.AllowSquash)
		assert.False(t, cfg.MergeStrategy.AllowMerge)
		assert.False(t, cfg.MergeStrategy.AllowRebase)
	})
}
