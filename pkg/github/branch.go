package github

import (
	"fmt"
	"net/http"

	"github.com/cli/go-gh/v2/pkg/api"
)

type BranchProtection struct {
	RequiredReviews      int      `json:"required_reviews"`
	DismissStaleReviews  bool     `json:"dismiss_stale_reviews"`
	RequireCodeOwners    bool     `json:"require_code_owners"`
	RequiredStatusChecks []string `json:"required_status_checks"`
	StrictStatusChecks   bool     `json:"strict_status_checks"`
	EnforceAdmins        bool     `json:"enforce_admins"`
	AllowForcePushes     bool     `json:"allow_force_pushes"`
	AllowDeletions       bool     `json:"allow_deletions"`
	RequireLinearHistory bool     `json:"require_linear_history"`
	RequireSignedCommits bool     `json:"require_signed_commits"`
}

type branchProtectionResponse struct {
	RequiredPullRequestReviews *struct {
		DismissStaleReviews          bool `json:"dismiss_stale_reviews"`
		RequireCodeOwnerReviews      bool `json:"require_code_owner_reviews"`
		RequiredApprovingReviewCount int  `json:"required_approving_review_count"`
	} `json:"required_pull_request_reviews"`
	RequiredStatusChecks *struct {
		Strict   bool     `json:"strict"`
		Contexts []string `json:"contexts"`
	} `json:"required_status_checks"`
	EnforceAdmins        *struct{ Enabled bool } `json:"enforce_admins"`
	AllowForcePushes     *struct{ Enabled bool } `json:"allow_force_pushes"`
	AllowDeletions       *struct{ Enabled bool } `json:"allow_deletions"`
	RequireLinearHistory *struct{ Enabled bool } `json:"required_linear_history"`
	RequiredSignatures   *struct{ Enabled bool } `json:"required_signatures"`
}

func (c *Client) GetBranchProtection(branch string) (*BranchProtection, error) {
	var resp branchProtectionResponse
	path := c.RepoPath("branches", branch, "protection")
	err := c.Get(path, &resp)
	if err != nil {
		var httpErr *api.HTTPError
		if isHTTPError(err, http.StatusNotFound, &httpErr) {
			return nil, nil // not protected
		}
		return nil, fmt.Errorf("failed to get branch protection: %w", err)
	}

	bp := &BranchProtection{}
	if resp.RequiredPullRequestReviews != nil {
		bp.RequiredReviews = resp.RequiredPullRequestReviews.RequiredApprovingReviewCount
		bp.DismissStaleReviews = resp.RequiredPullRequestReviews.DismissStaleReviews
		bp.RequireCodeOwners = resp.RequiredPullRequestReviews.RequireCodeOwnerReviews
	}
	if resp.RequiredStatusChecks != nil {
		bp.StrictStatusChecks = resp.RequiredStatusChecks.Strict
		bp.RequiredStatusChecks = resp.RequiredStatusChecks.Contexts
	}
	if resp.EnforceAdmins != nil {
		bp.EnforceAdmins = resp.EnforceAdmins.Enabled
	}
	if resp.AllowForcePushes != nil {
		bp.AllowForcePushes = resp.AllowForcePushes.Enabled
	}
	if resp.AllowDeletions != nil {
		bp.AllowDeletions = resp.AllowDeletions.Enabled
	}
	if resp.RequireLinearHistory != nil {
		bp.RequireLinearHistory = resp.RequireLinearHistory.Enabled
	}
	if resp.RequiredSignatures != nil {
		bp.RequireSignedCommits = resp.RequiredSignatures.Enabled
	}

	return bp, nil
}

func (c *Client) SetBranchProtection(branch string, bp *BranchProtection) error {
	path := c.RepoPath("branches", branch, "protection")

	body := map[string]interface{}{
		"enforce_admins":         bp.EnforceAdmins,
		"allow_force_pushes":     bp.AllowForcePushes,
		"allow_deletions":        bp.AllowDeletions,
		"required_linear_history": bp.RequireLinearHistory,
		"restrictions":           nil,
	}

	if bp.RequiredReviews > 0 {
		body["required_pull_request_reviews"] = map[string]interface{}{
			"dismiss_stale_reviews":           bp.DismissStaleReviews,
			"require_code_owner_reviews":      bp.RequireCodeOwners,
			"required_approving_review_count": bp.RequiredReviews,
		}
	} else {
		body["required_pull_request_reviews"] = nil
	}

	if len(bp.RequiredStatusChecks) > 0 {
		body["required_status_checks"] = map[string]interface{}{
			"strict":   bp.StrictStatusChecks,
			"contexts": bp.RequiredStatusChecks,
		}
	} else {
		body["required_status_checks"] = nil
	}

	err := c.Put(path, body, nil)
	if err != nil {
		return fmt.Errorf("failed to set branch protection: %w", err)
	}

	// Signed commits require a separate endpoint
	if bp.RequireSignedCommits {
		sigPath := c.RepoPath("branches", branch, "protection", "required_signatures")
		if err := c.Post(sigPath, nil, nil); err != nil {
			return fmt.Errorf("failed to enable signed commits: %w", err)
		}
	}

	return nil
}

func (c *Client) DeleteBranchProtection(branch string) error {
	path := c.RepoPath("branches", branch, "protection")
	err := c.Delete(path, nil)
	if err != nil {
		return fmt.Errorf("failed to delete branch protection: %w", err)
	}
	return nil
}

func (c *Client) ListProtectedBranches() ([]string, error) {
	var resp []struct {
		Name      string `json:"name"`
		Protected bool   `json:"protected"`
	}
	err := c.Get(c.RepoPath("branches")+"?protected=true", &resp)
	if err != nil {
		return nil, fmt.Errorf("failed to list protected branches: %w", err)
	}

	var branches []string
	for _, b := range resp {
		branches = append(branches, b.Name)
	}
	return branches, nil
}

func isHTTPError(err error, statusCode int, target **api.HTTPError) bool {
	if httpErr, ok := err.(*api.HTTPError); ok {
		*target = httpErr
		return httpErr.StatusCode == statusCode
	}
	return false
}
