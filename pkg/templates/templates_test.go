package templates

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestContributing(t *testing.T) {
	tests := []struct {
		name    string
		repo    string
		owner   string
		wantLen int
	}{
		{
			name:    "standard repo",
			repo:    "my-project",
			owner:   "myorg",
			wantLen: 1,
		},
		{
			name:    "different owner",
			repo:    "gh-secure",
			owner:   "sah1l",
			wantLen: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Contributing(tt.repo, tt.owner)
			assert.NotEmpty(t, result)
			assert.Contains(t, result, tt.repo)
			assert.Contains(t, result, tt.owner)
			assert.Contains(t, result, "## How to Contribute")
		})
	}
}

func TestSecurity(t *testing.T) {
	tests := []struct {
		name  string
		repo  string
		owner string
	}{
		{
			name:  "standard repo",
			repo:  "my-project",
			owner: "myorg",
		},
		{
			name:  "different owner",
			repo:  "gh-secure",
			owner: "sah1l",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Security(tt.repo, tt.owner)
			assert.NotEmpty(t, result)
			assert.Contains(t, result, tt.repo)
			assert.Contains(t, result, "# Security Policy")
			assert.Contains(t, result, "## Reporting a Vulnerability")
		})
	}
}

func TestCodeOfConduct(t *testing.T) {
	t.Run("standard template", func(t *testing.T) {
		result := CodeOfConduct("my-project", "myorg")
		assert.NotEmpty(t, result)
		assert.Contains(t, result, "## Our Pledge")
		assert.Contains(t, result, "myorg")
	})
}

func TestCodeowners(t *testing.T) {
	tests := []struct {
		name  string
		owner string
	}{
		{
			name:  "single owner",
			owner: "myorg",
		},
		{
			name:  "team owner",
			owner: "@myorg/security",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Codeowners(tt.owner)
			assert.NotEmpty(t, result)
			assert.Contains(t, result, tt.owner)
		})
	}
}

func TestDependabot(t *testing.T) {
	t.Run("single ecosystem", func(t *testing.T) {
		result := Dependabot([]string{"gomod"})
		assert.NotEmpty(t, result)
		assert.Contains(t, result, "gomod")
		assert.Contains(t, result, "package-ecosystem")
	})

	t.Run("multiple ecosystems", func(t *testing.T) {
		result := Dependabot([]string{"gomod", "npm", "docker"})
		assert.NotEmpty(t, result)
		assert.Contains(t, result, "gomod")
		assert.Contains(t, result, "npm")
		assert.Contains(t, result, "docker")
	})

	t.Run("empty ecosystems", func(t *testing.T) {
		result := Dependabot([]string{})
		// Should still produce valid YAML
		assert.NotEmpty(t, result)
		assert.Contains(t, result, "updates:")
	})
}

func TestDefaultDependabot(t *testing.T) {
	t.Run("default template", func(t *testing.T) {
		result := DefaultDependabot()
		assert.NotEmpty(t, result)
		assert.Contains(t, result, "version: 2")
		assert.Contains(t, result, "package-ecosystem")
		assert.Contains(t, result, "github-actions")
	})
}

func TestTemplatesDoNotPanic(t *testing.T) {
	// All templates should handle empty strings gracefully
	assert.NotPanics(t, func() {
		Contributing("", "")
	})
	assert.NotPanics(t, func() {
		Security("", "")
	})
	assert.NotPanics(t, func() {
		CodeOfConduct("", "")
	})
	assert.NotPanics(t, func() {
		Codeowners("")
	})
	assert.NotPanics(t, func() {
		Dependabot(nil)
	})
	assert.NotPanics(t, func() {
		DefaultDependabot()
	})
}

func TestContributingContent(t *testing.T) {
	result := Contributing("test-repo", "test-owner")
	require.NotEmpty(t, result)

	// Check for expected sections
	assert.Contains(t, result, "# Contributing to test-repo")
	assert.Contains(t, result, "test-owner")
	assert.Contains(t, result, "## How to Contribute")
	assert.Contains(t, result, "## Pull Request Guidelines")
	assert.Contains(t, result, "## Code of Conduct")
}

func TestSecurityContent(t *testing.T) {
	result := Security("test-repo", "test-owner")
	require.NotEmpty(t, result)

	// Check for expected sections
	assert.Contains(t, result, "# Security Policy")
	assert.Contains(t, result, "test-repo")
	assert.Contains(t, result, "## Reporting a Vulnerability")
}
