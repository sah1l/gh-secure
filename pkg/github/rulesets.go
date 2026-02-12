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
	RequiredApprovingReviewCount    int      `json:"required_approving_review_count"`
	DismissStaleReviewsOnPush      bool     `json:"dismiss_stale_reviews_on_push"`
	RequireCodeOwnerReview         bool     `json:"require_code_owner_review"`
	RequireLastPushApproval        bool     `json:"require_last_push_approval"`
	RequiredReviewThreadResolution bool     `json:"required_review_thread_resolution"`
	AllowedMergeMethods            []string `json:"allowed_merge_methods,omitempty"`
	RequiredStatusChecks           []struct {
		Context string `json:"context"`
	} `json:"required_status_checks,omitempty"`
	StrictRequiredStatusChecksPolicy bool `json:"strict_required_status_checks_policy,omitempty"`
}

type BypassActor struct {
	ActorID    int    `json:"actor_id"`
	ActorType  string `json:"actor_type"`
	BypassMode string `json:"bypass_mode"`
}

type Rule struct {
	Type       string          `json:"type"`
	Parameters *RuleParameters `json:"parameters,omitempty"`
}

type Ruleset struct {
	ID           int               `json:"id,omitempty"`
	Name         string            `json:"name"`
	Target       string            `json:"target"`
	Enforcement  string            `json:"enforcement"`
	BypassActors []BypassActor     `json:"bypass_actors,omitempty"`
	Conditions   RulesetConditions `json:"conditions"`
	Rules        []Rule            `json:"rules"`
}

func (c *Client) ListRulesets() ([]Ruleset, error) {
	var rulesets []Ruleset
	err := c.Get(c.RepoPath("rulesets"), &rulesets)
	if err != nil {
		return nil, fmt.Errorf("failed to list rulesets: %w", err)
	}
	return rulesets, nil
}

func (c *Client) ListRulesetsDetailed() ([]Ruleset, error) {
	summaries, err := c.ListRulesets()
	if err != nil {
		return nil, err
	}
	detailed := make([]Ruleset, 0, len(summaries))
	for _, s := range summaries {
		rs, err := c.GetRuleset(s.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to get ruleset %d (%s): %w", s.ID, s.Name, err)
		}
		detailed = append(detailed, *rs)
	}
	return detailed, nil
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

// RulesetOptions holds all parameters for building a protection ruleset.
type RulesetOptions struct {
	Name                string
	Branch              string
	Reviews             int
	DismissStale        bool
	CodeOwners          bool
	LinearHistory       bool
	SignedCommits       bool
	AllowedMergeMethods []string
	BypassActors        []BypassActor
}

// BuildProtectionRuleset creates a standard branch protection ruleset.
func BuildProtectionRuleset(opts RulesetOptions) *Ruleset {
	rs := &Ruleset{
		Name:         opts.Name,
		Target:       "branch",
		Enforcement:  "active",
		BypassActors: opts.BypassActors,
		Conditions: RulesetConditions{
			RefName: struct {
				Include []string `json:"include"`
				Exclude []string `json:"exclude"`
			}{
				Include: []string{"refs/heads/" + opts.Branch},
				Exclude: []string{},
			},
		},
		Rules: []Rule{
			{Type: "deletion"},
			{Type: "non_fast_forward"},
		},
	}

	if opts.Reviews > 0 {
		prParams := &RuleParameters{
			RequiredApprovingReviewCount: opts.Reviews,
			DismissStaleReviewsOnPush:   opts.DismissStale,
			RequireCodeOwnerReview:      opts.CodeOwners,
			RequireLastPushApproval:     false,
		}
		if len(opts.AllowedMergeMethods) > 0 {
			prParams.AllowedMergeMethods = opts.AllowedMergeMethods
		}
		rs.Rules = append(rs.Rules, Rule{
			Type:       "pull_request",
			Parameters: prParams,
		})
	}

	if opts.LinearHistory {
		rs.Rules = append(rs.Rules, Rule{Type: "required_linear_history"})
	}

	if opts.SignedCommits {
		rs.Rules = append(rs.Rules, Rule{Type: "required_signatures"})
	}

	return rs
}
