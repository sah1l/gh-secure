package github

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/cli/go-gh/v2/pkg/api"
	"github.com/cli/go-gh/v2/pkg/repository"
)

type Client struct {
	rest *api.RESTClient
	repo repository.Repository
}

func NewClient(repoOverride string) (*Client, error) {
	opts := api.ClientOptions{}
	rest, err := api.NewRESTClient(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create REST client: %w", err)
	}

	var repo repository.Repository
	if repoOverride != "" {
		repo, err = repository.Parse(repoOverride)
		if err != nil {
			return nil, fmt.Errorf("invalid repo format %q: %w", repoOverride, err)
		}
	} else {
		repo, err = repository.Current()
		if err != nil {
			return nil, fmt.Errorf("could not determine repository (use --repo flag or run from a git repo): %w", err)
		}
	}

	return &Client{rest: rest, repo: repo}, nil
}

func encodeBody(body interface{}) io.Reader {
	if body == nil {
		return nil
	}
	b, err := json.Marshal(body)
	if err != nil {
		return nil
	}
	return bytes.NewReader(b)
}

func (c *Client) Get(path string, result interface{}) error {
	return c.rest.Get(path, result)
}

func (c *Client) Put(path string, body interface{}, result interface{}) error {
	return c.rest.Put(path, encodeBody(body), result)
}

func (c *Client) Patch(path string, body interface{}, result interface{}) error {
	return c.rest.Patch(path, encodeBody(body), result)
}

func (c *Client) Post(path string, body interface{}, result interface{}) error {
	return c.rest.Post(path, encodeBody(body), result)
}

func (c *Client) Delete(path string, body interface{}) error {
	if body != nil {
		// go-gh's Delete doesn't support a request body, so use Do for cases like file deletion
		return c.rest.Do("DELETE", path, encodeBody(body), nil)
	}
	return c.rest.Delete(path, nil)
}

func (c *Client) Owner() string {
	return c.repo.Owner
}

func (c *Client) RepoName() string {
	return c.repo.Name
}

func (c *Client) RepoPath(parts ...string) string {
	base := fmt.Sprintf("repos/%s/%s", c.Owner(), c.RepoName())
	for _, p := range parts {
		base += "/" + p
	}
	return base
}
