package github

import (
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/cli/go-gh/v2/pkg/api"
)

type RepoFile struct {
	Path    string `json:"path"`
	SHA     string `json:"sha"`
	Content string `json:"content"`
	Exists  bool   `json:"-"`
}

type fileResponse struct {
	SHA     string `json:"sha"`
	Content string `json:"content"`
	Path    string `json:"path"`
}

func (c *Client) GetFile(path string) (*RepoFile, error) {
	var resp fileResponse
	err := c.Get(c.RepoPath("contents", path), &resp)
	if err != nil {
		var httpErr *api.HTTPError
		if isHTTPError(err, http.StatusNotFound, &httpErr) {
			return &RepoFile{Path: path, Exists: false}, nil
		}
		return nil, fmt.Errorf("failed to get file %s: %w", path, err)
	}

	decoded, _ := base64.StdEncoding.DecodeString(resp.Content)
	return &RepoFile{
		Path:    path,
		SHA:     resp.SHA,
		Content: string(decoded),
		Exists:  true,
	}, nil
}

func (c *Client) CreateOrUpdateFile(path, message, content string) error {
	encoded := base64.StdEncoding.EncodeToString([]byte(content))

	body := map[string]interface{}{
		"message": message,
		"content": encoded,
	}

	// Check if file exists to get SHA for update
	existing, err := c.GetFile(path)
	if err != nil {
		return err
	}
	if existing.Exists {
		body["sha"] = existing.SHA
	}

	return c.Put(c.RepoPath("contents", path), body, nil)
}

func (c *Client) DeleteFile(path, message, sha string) error {
	body := map[string]interface{}{
		"message": message,
		"sha":     sha,
	}
	return c.Delete(c.RepoPath("contents", path), body)
}

// CreateOrUpdateFileOnBranch creates or updates a file on a specific branch.
func (c *Client) CreateOrUpdateFileOnBranch(path, message, content, branch string) error {
	encoded := base64.StdEncoding.EncodeToString([]byte(content))

	body := map[string]interface{}{
		"message": message,
		"content": encoded,
		"branch":  branch,
	}

	// Check if file exists on that branch to get SHA for update
	existing, err := c.GetFile(path)
	if err != nil {
		return err
	}
	if existing.Exists {
		body["sha"] = existing.SHA
	}

	return c.Put(c.RepoPath("contents", path), body, nil)
}

// GetBranchSHA returns the latest commit SHA of a branch.
func (c *Client) GetBranchSHA(branch string) (string, error) {
	var resp struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	err := c.Get(c.RepoPath("git", "ref", "heads", branch), &resp)
	if err != nil {
		return "", fmt.Errorf("failed to get branch SHA for %s: %w", branch, err)
	}
	return resp.Object.SHA, nil
}

// CreateBranch creates a new branch from the given SHA.
func (c *Client) CreateBranch(name, sha string) error {
	body := map[string]interface{}{
		"ref": "refs/heads/" + name,
		"sha": sha,
	}
	return c.Post(c.RepoPath("git", "refs"), body, nil)
}

// PullRequest represents a GitHub pull request.
type PullRequest struct {
	Number  int    `json:"number"`
	HTMLURL string `json:"html_url"`
}

// CreatePullRequest creates a PR from head into base.
func (c *Client) CreatePullRequest(title, body, head, base string) (*PullRequest, error) {
	payload := map[string]interface{}{
		"title": title,
		"body":  body,
		"head":  head,
		"base":  base,
	}
	var pr PullRequest
	err := c.Post(c.RepoPath("pulls"), payload, &pr)
	if err != nil {
		return nil, fmt.Errorf("failed to create pull request: %w", err)
	}
	return &pr, nil
}

// DetectEcosystems checks for common package manager files and returns detected ecosystems.
func (c *Client) DetectEcosystems() ([]string, error) {
	indicators := map[string]string{
		"package.json":    "npm",
		"go.mod":          "gomod",
		"requirements.txt": "pip",
		"Pipfile":         "pip",
		"pyproject.toml":  "pip",
		"Gemfile":         "bundler",
		"pom.xml":         "maven",
		"build.gradle":    "gradle",
		"Cargo.toml":      "cargo",
		"composer.json":   "composer",
		"mix.exs":         "mix",
		"Package.swift":   "swift",
		"pubspec.yaml":    "pub",
		".terraform.lock.hcl": "terraform",
		"Dockerfile":      "docker",
	}

	var ecosystems []string
	seen := make(map[string]bool)

	for file, ecosystem := range indicators {
		f, err := c.GetFile(file)
		if err != nil {
			continue
		}
		if f.Exists && !seen[ecosystem] {
			ecosystems = append(ecosystems, ecosystem)
			seen[ecosystem] = true
		}
	}

	return ecosystems, nil
}
