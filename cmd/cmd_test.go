package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/sah1l/gh-secure/pkg/config"
	gh "github.com/sah1l/gh-secure/pkg/github"
)

func TestOutputJSON(t *testing.T) {
	t.Run("valid data", func(t *testing.T) {
		data := map[string]string{
			"name": "test",
			"version": "1.0",
		}

		// Capture stdout
		oldStdout := os.Stdout
		defer func() { os.Stdout = oldStdout }()

		r, w, err := os.Pipe()
		require.NoError(t, err)
		os.Stdout = w

		err = outputJSON(data)
		w.Close()

		require.NoError(t, err)

		var output map[string]string
		dec := json.NewDecoder(r)
		dec.Decode(&output)

		assert.Equal(t, "test", output["name"])
		assert.Equal(t, "1.0", output["version"])
	})

	t.Run("empty data", func(t *testing.T) {
		oldStdout := os.Stdout
		defer func() { os.Stdout = oldStdout }()

		r, w, err := os.Pipe()
		require.NoError(t, err)
		os.Stdout = w

		err = outputJSON(map[string]interface{}{})
		w.Close()
		r.Close()

		require.NoError(t, err)
	})
}

func TestHasActiveRulesets(t *testing.T) {
	t.Run("active ruleset", func(t *testing.T) {
		rulesets := []gh.Ruleset{
			{Enforcement: "active"},
		}
		assert.True(t, hasActiveRulesets(rulesets))
	})

	t.Run("disabled ruleset", func(t *testing.T) {
		rulesets := []gh.Ruleset{
			{Enforcement: "disabled"},
		}
		assert.False(t, hasActiveRulesets(rulesets))
	})

	t.Run("empty", func(t *testing.T) {
		assert.False(t, hasActiveRulesets(nil))
		assert.False(t, hasActiveRulesets([]gh.Ruleset{}))
	})
}

// Helper to test config rendering with captured output
func TestRenderConfigSummary(t *testing.T) {
	// This test just verifies the function doesn't panic
	cfg := &config.Config{
		Version:    1,
		Visibility: "private",
		MergeStrategy: config.MergeStrategy{
			AllowSquash: true,
			AllowMerge:  false,
			AllowRebase: false,
		},
		DeleteBranchOnMerge: true,
		Security: config.SecurityConfig{
			VulnerabilityAlerts: true,
			SecretScanning:       true,
		},
		Rulesets: []config.RulesetConfig{
			{
				Name:            "Protect main",
				Branches:        []string{"main"},
				RequiredReviews: 2,
			},
		},
	}

	// Capture output to avoid printing during tests
	oldStdout := os.Stdout
	defer func() { os.Stdout = oldStdout }()

	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w

	renderConfigSummary(cfg, "main")

	w.Close()

	// Just verify it completes without panic
	// In a real test, we'd parse the output
	buf := new(bytes.Buffer)
	buf.ReadFrom(r)
	assert.NotNil(t, buf)
}
