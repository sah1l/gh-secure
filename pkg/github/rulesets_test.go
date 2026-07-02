package github

import (
	"errors"
	"net/http"
	"testing"

	"github.com/cli/go-gh/v2/pkg/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildProtectionRuleset(t *testing.T) {
	t.Run("basic options", func(t *testing.T) {
		opts := RulesetOptions{
			Name:    "Protect main",
			Branch:  "main",
			Reviews: 1,
		}

		rs := BuildProtectionRuleset(opts)

		assert.Equal(t, "Protect main", rs.Name)
		assert.Equal(t, "branch", rs.Target)
		assert.Equal(t, "active", rs.Enforcement)
		assert.Contains(t, rs.Conditions.RefName.Include, "refs/heads/main")

		// Should have deletion and non_fast_forward rules
		ruleTypes := make([]string, len(rs.Rules))
		for i, r := range rs.Rules {
			ruleTypes[i] = r.Type
		}
		assert.Contains(t, ruleTypes, "deletion")
		assert.Contains(t, ruleTypes, "non_fast_forward")
	})

	t.Run("with review requirements", func(t *testing.T) {
		opts := RulesetOptions{
			Name:       "Protect main",
			Branch:     "main",
			Reviews:    2,
			DismissStale: true,
			CodeOwners: true,
		}

		rs := BuildProtectionRuleset(opts)

		// Find pull_request rule
		var prRule *Rule
		for i := range rs.Rules {
			if rs.Rules[i].Type == "pull_request" {
				prRule = &rs.Rules[i]
				break
			}
		}
		require.NotNil(t, prRule, "pull_request rule should exist")
		require.NotNil(t, prRule.Parameters)
		assert.Equal(t, 2, prRule.Parameters.RequiredApprovingReviewCount)
		assert.True(t, prRule.Parameters.DismissStaleReviewsOnPush)
		assert.True(t, prRule.Parameters.RequireCodeOwnerReview)
	})

	t.Run("with merge methods", func(t *testing.T) {
		opts := RulesetOptions{
			Name:               "Protect main",
			Branch:             "main",
			Reviews:            1,
			AllowedMergeMethods: []string{"squash", "rebase"},
		}

		rs := BuildProtectionRuleset(opts)

		var prRule *Rule
		for i := range rs.Rules {
			if rs.Rules[i].Type == "pull_request" {
				prRule = &rs.Rules[i]
				break
			}
		}
		require.NotNil(t, prRule)
		assert.ElementsMatch(t, []string{"squash", "rebase"}, prRule.Parameters.AllowedMergeMethods)
	})

	t.Run("with linear history", func(t *testing.T) {
		opts := RulesetOptions{
			Name:          "Protect main",
			Branch:        "main",
			Reviews:       1,
			LinearHistory: true,
		}

		rs := BuildProtectionRuleset(opts)

		hasLinearHistory := false
		for _, r := range rs.Rules {
			if r.Type == "required_linear_history" {
				hasLinearHistory = true
				break
			}
		}
		assert.True(t, hasLinearHistory)
	})

	t.Run("with signed commits", func(t *testing.T) {
		opts := RulesetOptions{
			Name:          "Protect main",
			Branch:        "main",
			Reviews:       1,
			SignedCommits: true,
		}

		rs := BuildProtectionRuleset(opts)

		hasSignedCommits := false
		for _, r := range rs.Rules {
			if r.Type == "required_signatures" {
				hasSignedCommits = true
				break
			}
		}
		assert.True(t, hasSignedCommits)
	})

	t.Run("with bypass actors", func(t *testing.T) {
		opts := RulesetOptions{
			Name:    "Protect main",
			Branch:  "main",
			Reviews: 1,
			BypassActors: []BypassActor{
				{ActorID: 5, ActorType: "RepositoryRole"},
			},
		}

		rs := BuildProtectionRuleset(opts)

		assert.Len(t, rs.BypassActors, 1)
		assert.Equal(t, 5, rs.BypassActors[0].ActorID)
	})

	t.Run("no reviews", func(t *testing.T) {
		opts := RulesetOptions{
			Name:   "Protect main",
			Branch: "main",
			Reviews: 0,
		}

		rs := BuildProtectionRuleset(opts)

		// Should not have pull_request rule
		for _, r := range rs.Rules {
			assert.NotEqual(t, "pull_request", r.Type)
		}
	})
}

func TestIsRuleViolation(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		want     bool
	}{
		{
			name:     "nil error",
			err:      nil,
			want:     false,
		},
		{
			name:     "non-HTTP error",
			err:      errors.New("some error"),
			want:     false,
		},
		{
			name:     "HTTP 409 rule violation",
			err:      &api.HTTPError{StatusCode: http.StatusConflict, Message: "Rule violation"},
			want:     true,
		},
		{
			name:     "HTTP 200 OK",
			err:      &api.HTTPError{StatusCode: http.StatusOK},
			want:     false,
		},
		{
			name:     "HTTP 404 not found",
			err:      &api.HTTPError{StatusCode: http.StatusNotFound},
			want:     false,
		},
		{
			name:     "HTTP 422 unprocessable",
			err:      &api.HTTPError{StatusCode: http.StatusUnprocessableEntity},
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsRuleViolation(tt.err)
			assert.Equal(t, tt.want, got)
		})
	}
}
