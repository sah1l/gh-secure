package github

import "fmt"

type License struct {
	Key    string `json:"key"`
	Name   string `json:"name"`
	SPDXID string `json:"spdx_id"`
}

type RepoSettings struct {
	Visibility          string   `json:"visibility"`
	DefaultBranch       string   `json:"default_branch"`
	AllowSquashMerge    bool     `json:"allow_squash_merge"`
	AllowMergeCommit    bool     `json:"allow_merge_commit"`
	AllowRebaseMerge    bool     `json:"allow_rebase_merge"`
	DeleteBranchOnMerge bool     `json:"delete_branch_on_merge"`
	HasWiki             bool     `json:"has_wiki"`
	HasIssues           bool     `json:"has_issues"`
	HasProjects         bool     `json:"has_projects"`
	License             *License `json:"license"`
	Description         string   `json:"description"`
	Topics              []string `json:"topics"`
}

type repoResponse struct {
	Visibility          string   `json:"visibility"`
	DefaultBranch       string   `json:"default_branch"`
	AllowSquashMerge    bool     `json:"allow_squash_merge"`
	AllowMergeCommit    bool     `json:"allow_merge_commit"`
	AllowRebaseMerge    bool     `json:"allow_rebase_merge"`
	DeleteBranchOnMerge bool     `json:"delete_branch_on_merge"`
	HasWiki             bool     `json:"has_wiki"`
	HasIssues           bool     `json:"has_issues"`
	HasProjects         bool     `json:"has_projects"`
	License             *License `json:"license"`
	Description         string   `json:"description"`
	Topics              []string `json:"topics"`
}

func (c *Client) GetRepoSettings() (*RepoSettings, error) {
	var resp repoResponse
	err := c.Get(c.RepoPath(), &resp)
	if err != nil {
		return nil, fmt.Errorf("failed to get repo settings: %w", err)
	}

	return &RepoSettings{
		Visibility:          resp.Visibility,
		DefaultBranch:       resp.DefaultBranch,
		AllowSquashMerge:    resp.AllowSquashMerge,
		AllowMergeCommit:    resp.AllowMergeCommit,
		AllowRebaseMerge:    resp.AllowRebaseMerge,
		DeleteBranchOnMerge: resp.DeleteBranchOnMerge,
		HasWiki:             resp.HasWiki,
		HasIssues:           resp.HasIssues,
		HasProjects:         resp.HasProjects,
		License:             resp.License,
		Description:         resp.Description,
		Topics:              resp.Topics,
	}, nil
}

func (c *Client) UpdateRepoSettings(settings map[string]interface{}) error {
	err := c.Patch(c.RepoPath(), settings, nil)
	if err != nil {
		return fmt.Errorf("failed to update repo settings: %w", err)
	}
	return nil
}

func (c *Client) SetVisibility(visibility string) error {
	return c.UpdateRepoSettings(map[string]interface{}{
		"visibility": visibility,
	})
}

func (c *Client) SetMergeStrategies(squash, merge, rebase bool) error {
	return c.UpdateRepoSettings(map[string]interface{}{
		"allow_squash_merge": squash,
		"allow_merge_commit": merge,
		"allow_rebase_merge": rebase,
	})
}

func (c *Client) SetDeleteBranchOnMerge(enabled bool) error {
	return c.UpdateRepoSettings(map[string]interface{}{
		"delete_branch_on_merge": enabled,
	})
}
