package github

import (
	"fmt"
	"net/http"

	"github.com/cli/go-gh/v2/pkg/api"
)

type RulesetConditions struct {
	RefName struct {
		Include []string `json:"include"`
		Exclude []string `json:"exclude"`
	} `json:"ref_name"`
}

type RuleParameters struct {
	RequiredApprovingReviewCount int  `json:"required_approving_review_count,omitempty"`
	DismissStaleReviewsOnPush   bool `json:"dismiss_stale_reviews_on_push,omitempty"`
	RequireCodeOwnerReview      bool `json:"require_code_owner_review,omitempty"`
	RequireLastPushApproval     bool `json:"require_last_push_approval,omitempty"`
	RequiredStatusChecks        []struct {
		Context string `json:"context"`
	} `json:"required_status_checks,omitempty"`
	StrictRequiredStatusChecksPolicy bool `json:"strict_required_status_checks_policy,omitempty"`
}

type Rule struct {
	Type       string          `json:"type"`
	Parameters *RuleParameters `json:"parameters,omitempty"`
}

type Ruleset struct {
	ID          int               `json:"id,omitempty"`
	Name        string            `json:"name"`
	Target      string            `json:"target"`
	Enforcement string            `json:"enforcement"`
	Conditions  RulesetConditions `json:"conditions"`
	Rules       []Rule            `json:"rules"`
}

func (c *Client) ListRulesets() ([]Ruleset, error) {
	var rulesets []Ruleset
	err := c.Get(c.RepoPath("rulesets"), &rulesets)
	if err != nil {
		return nil, fmt.Errorf("failed to list rulesets: %w", err)
	}
	return rulesets, nil
}

func (c *Client) GetRuleset(id int) (*Ruleset, error) {
	var rs Ruleset
	err := c.Get(fmt.Sprintf("%s/%d", c.RepoPath("rulesets"), id), &rs)
	if err != nil {
		return nil, fmt.Errorf("failed to get ruleset: %w", err)
	}
	return &rs, nil
}

func (c *Client) CreateRuleset(rs *Ruleset) error {
	err := c.Post(c.RepoPath("rulesets"), rs, nil)
	if err != nil {
		return fmt.Errorf("failed to create ruleset: %w", err)
	}
	return nil
}

func (c *Client) UpdateRuleset(id int, rs *Ruleset) error {
	err := c.Put(fmt.Sprintf("%s/%d", c.RepoPath("rulesets"), id), rs, nil)
	if err != nil {
		return fmt.Errorf("failed to update ruleset: %w", err)
	}
	return nil
}

func (c *Client) DeleteRuleset(id int) error {
	err := c.Delete(fmt.Sprintf("%s/%d", c.RepoPath("rulesets"), id), nil)
	if err != nil {
		return fmt.Errorf("failed to delete ruleset: %w", err)
	}
	return nil
}

func (c *Client) SupportsRulesets() bool {
	var result interface{}
	err := c.Get(c.RepoPath("rulesets"), &result)
	if err != nil {
		var httpErr *api.HTTPError
		if isHTTPError(err, http.StatusNotFound, &httpErr) || isHTTPError(err, http.StatusForbidden, &httpErr) {
			return false
		}
	}
	return true
}

// BuildProtectionRuleset creates a standard branch protection ruleset.
func BuildProtectionRuleset(name, branch string, reviews int, dismissStale, codeOwners, linearHistory, signedCommits bool) *Ruleset {
	rs := &Ruleset{
		Name:        name,
		Target:      "branch",
		Enforcement: "active",
		Conditions: RulesetConditions{
			RefName: struct {
				Include []string `json:"include"`
				Exclude []string `json:"exclude"`
			}{
				Include: []string{"refs/heads/" + branch},
				Exclude: []string{},
			},
		},
		Rules: []Rule{
			{Type: "deletion"},
			{Type: "non_fast_forward"},
		},
	}

	if reviews > 0 {
		rs.Rules = append(rs.Rules, Rule{
			Type: "pull_request",
			Parameters: &RuleParameters{
				RequiredApprovingReviewCount: reviews,
				DismissStaleReviewsOnPush:   dismissStale,
				RequireCodeOwnerReview:      codeOwners,
				RequireLastPushApproval:     false,
			},
		})
	}

	if linearHistory {
		rs.Rules = append(rs.Rules, Rule{Type: "required_linear_history"})
	}

	if signedCommits {
		rs.Rules = append(rs.Rules, Rule{Type: "required_signatures"})
	}

	return rs
}
