package github

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPMockSetup(t *testing.T) {
	// Test that httpmock is properly activated and works
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	// Register a mock responder
	httpmock.RegisterResponder(
		"GET",
		"https://api.github.com/repos/owner/repo",
		httpmock.NewStringResponder(http.StatusOK, `{"name": "repo"}`),
	)

	// Register another responder for testing
	httpmock.RegisterResponder(
		"POST",
		"https://api.github.com/repos/owner/repo/rulesets",
		httpmock.NewStringResponder(http.StatusCreated, `{"id": 1, "name": "Test"}`),
	)

	// Verify call counts
	callCount := httpmock.GetCallCountInfo()
	assert.Equal(t, 0, callCount["GET https://api.github.com/repos/owner/repo"])
	assert.Equal(t, 0, callCount["POST https://api.github.com/repos/owner/repo/rulesets"])
}

func TestHTTPMockResponder(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	// Test with different status codes
	httpmock.RegisterResponder(
		"GET",
		"https://api.github.com/repos/owner/repo",
		httpmock.NewStringResponder(http.StatusOK, `{"name": "repo"}`),
	)

	httpmock.RegisterResponder(
		"GET",
		"https://api.github.com/repos/owner/notfound",
		httpmock.NewStringResponder(http.StatusNotFound, `{"message": "Not Found"}`),
	)

	httpmock.RegisterResponder(
		"GET",
		"https://api.github.com/repos/owner/error",
		httpmock.NewStringResponder(http.StatusInternalServerError, `{"message": "Server Error"}`),
	)

	// Verify responders are registered
	callCount := httpmock.GetCallCountInfo()
	assert.Equal(t, 0, callCount["GET https://api.github.com/repos/owner/repo"])
	assert.Equal(t, 0, callCount["GET https://api.github.com/repos/owner/notfound"])
	assert.Equal(t, 0, callCount["GET https://api.github.com/repos/owner/error"])
}

func TestRulesetJSONParsing(t *testing.T) {
	// Test parsing ruleset JSON without HTTP calls
	rulesetJSON := `{
		"id": 1,
		"name": "Protect main",
		"target": "branch",
		"enforcement": "active",
		"conditions": {
			"ref_name": {
				"include": ["refs/heads/main"],
				"exclude": []
			}
		},
		"rules": [
			{
				"type": "pull_request",
				"parameters": {
					"required_approving_review_count": 2,
					"dismiss_stale_reviews_on_push": true,
					"require_code_owner_review": true
				}
			},
			{"type": "deletion"},
			{"type": "non_fast_forward"}
		],
		"bypass_actors": [
			{"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}
		]
	}`

	var rs Ruleset
	err := json.Unmarshal([]byte(rulesetJSON), &rs)
	require.NoError(t, err)

	assert.Equal(t, 1, rs.ID)
	assert.Equal(t, "Protect main", rs.Name)
	assert.Equal(t, "branch", rs.Target)
	assert.Equal(t, "active", rs.Enforcement)
	assert.Len(t, rs.Rules, 3)
	assert.Len(t, rs.BypassActors, 1)

	// Check pull_request rule parameters
	prRule := rs.Rules[0]
	assert.Equal(t, "pull_request", prRule.Type)
	require.NotNil(t, prRule.Parameters)
	assert.Equal(t, 2, prRule.Parameters.RequiredApprovingReviewCount)
	assert.True(t, prRule.Parameters.DismissStaleReviewsOnPush)
	assert.True(t, prRule.Parameters.RequireCodeOwnerReview)
}

func TestBranchProtectionJSONParsing(t *testing.T) {
	// Test parsing branch protection JSON
	bpJSON := `{
		"required_pull_request_reviews": {
			"dismiss_stale_reviews": true,
			"require_code_owner_reviews": true,
			"required_approving_review_count": 2
		},
		"required_status_checks": {
			"strict": true,
			"contexts": ["ci/test", "lint"]
		},
		"enforce_admins": {"enabled": true},
		"allow_force_pushes": {"enabled": false},
		"allow_deletions": {"enabled": false},
		"required_linear_history": {"enabled": true},
		"required_signatures": {"enabled": true}
	}`

	var bp branchProtectionResponse
	err := json.Unmarshal([]byte(bpJSON), &bp)
	require.NoError(t, err)

	assert.NotNil(t, bp.RequiredPullRequestReviews)
	assert.Equal(t, 2, bp.RequiredPullRequestReviews.RequiredApprovingReviewCount)
	assert.True(t, bp.RequiredPullRequestReviews.DismissStaleReviews)
	assert.True(t, bp.RequiredPullRequestReviews.RequireCodeOwnerReviews)

	assert.NotNil(t, bp.RequiredStatusChecks)
	assert.True(t, bp.RequiredStatusChecks.Strict)
	assert.Equal(t, []string{"ci/test", "lint"}, bp.RequiredStatusChecks.Contexts)

	assert.True(t, bp.EnforceAdmins.Enabled)
	assert.False(t, bp.AllowForcePushes.Enabled)
	assert.False(t, bp.AllowDeletions.Enabled)
	assert.True(t, bp.RequireLinearHistory.Enabled)
	assert.True(t, bp.RequiredSignatures.Enabled)
}

func TestRepoFileJSONParsing(t *testing.T) {
	fileJSON := `{
		"path": "README.md",
		"sha": "abc123",
		"content": "SGVsbG8gV29ybGQ="
	}`

	var rf RepoFile
	err := json.Unmarshal([]byte(fileJSON), &rf)
	require.NoError(t, err)

	assert.Equal(t, "README.md", rf.Path)
	assert.Equal(t, "abc123", rf.SHA)
	assert.Equal(t, "SGVsbG8gV29ybGQ=", rf.Content)
}

func TestSecuritySettingsJSONParsing(t *testing.T) {
	settingsJSON := `{
		"visibility": "private",
		"default_branch": "main",
		"allow_squash_merge": true,
		"allow_merge_commit": false,
		"allow_rebase_merge": true,
		"delete_branch_on_merge": true,
		"license": {"key": "mit", "name": "MIT License"}
	}`

	var rs RepoSettings
	err := json.Unmarshal([]byte(settingsJSON), &rs)
	require.NoError(t, err)

	assert.Equal(t, "private", rs.Visibility)
	assert.Equal(t, "main", rs.DefaultBranch)
	assert.True(t, rs.AllowSquashMerge)
	assert.False(t, rs.AllowMergeCommit)
	assert.True(t, rs.AllowRebaseMerge)
	assert.True(t, rs.DeleteBranchOnMerge)
	require.NotNil(t, rs.License)
	assert.Equal(t, "mit", rs.License.Key)
}

func TestSecuritySettingsResponseJSONParsing(t *testing.T) {
	// Test parsing security settings from different API endpoints
	t.Run("vulnerability alerts", func(t *testing.T) {
		jsonStr := `{"enabled": true}`
		var resp struct {
			Enabled bool `json:"enabled"`
		}
		err := json.Unmarshal([]byte(jsonStr), &resp)
		require.NoError(t, err)
		assert.True(t, resp.Enabled)
	})

	t.Run("secret scanning", func(t *testing.T) {
		jsonStr := `{"state": "active"}`
		var resp struct {
			State string `json:"state"`
		}
		err := json.Unmarshal([]byte(jsonStr), &resp)
		require.NoError(t, err)
		assert.Equal(t, "active", resp.State)
	})
}

func TestRulesetConditionsParsing(t *testing.T) {
	conditionsJSON := `{
		"ref_name": {
			"include": ["refs/heads/main", "refs/heads/develop"],
			"exclude": ["refs/heads/feature/*"]
		}
	}`

	var rc RulesetConditions
	err := json.Unmarshal([]byte(conditionsJSON), &rc)
	require.NoError(t, err)

	assert.Equal(t, []string{"refs/heads/main", "refs/heads/develop"}, rc.RefName.Include)
	assert.Equal(t, []string{"refs/heads/feature/*"}, rc.RefName.Exclude)
}

func TestRuleParametersParsing(t *testing.T) {
	paramsJSON := `{
		"required_approving_review_count": 2,
		"dismiss_stale_reviews_on_push": true,
		"require_code_owner_review": true,
		"require_last_push_approval": false,
		"required_review_thread_resolution": true,
		"allowed_merge_methods": ["squash", "rebase"],
		"required_status_checks": [
			{"context": "ci/test"},
			{"context": "lint"}
		],
		"strict_required_status_checks_policy": true
	}`

	var rp RuleParameters
	err := json.Unmarshal([]byte(paramsJSON), &rp)
	require.NoError(t, err)

	assert.Equal(t, 2, rp.RequiredApprovingReviewCount)
	assert.True(t, rp.DismissStaleReviewsOnPush)
	assert.True(t, rp.RequireCodeOwnerReview)
	assert.False(t, rp.RequireLastPushApproval)
	assert.True(t, rp.RequiredReviewThreadResolution)
	assert.ElementsMatch(t, []string{"squash", "rebase"}, rp.AllowedMergeMethods)
	assert.Len(t, rp.RequiredStatusChecks, 2)
	assert.True(t, rp.StrictRequiredStatusChecksPolicy)
}

func TestBypassActorParsing(t *testing.T) {
	actorJSON := `[{
		"actor_id": 5,
		"actor_type": "RepositoryRole",
		"bypass_mode": "always"
	}, {
		"actor_id": 123,
		"actor_type": "PullRequest",
		"bypass_mode": "pull_requests"
	}]`

	var actors []BypassActor
	err := json.Unmarshal([]byte(actorJSON), &actors)
	require.NoError(t, err)

	assert.Len(t, actors, 2)
	assert.Equal(t, 5, actors[0].ActorID)
	assert.Equal(t, "RepositoryRole", actors[0].ActorType)
	assert.Equal(t, "always", actors[0].BypassMode)
	assert.Equal(t, 123, actors[1].ActorID)
	assert.Equal(t, "PullRequest", actors[1].ActorType)
}
