package github

import (
	"fmt"
	"net/http"

	"github.com/cli/go-gh/v2/pkg/api"
)

type SecuritySettings struct {
	VulnerabilityAlerts    bool `json:"vulnerability_alerts"`
	AutomatedSecurityFixes bool `json:"automated_security_fixes"`
	SecretScanning         bool `json:"secret_scanning"`
	SecretScanningPushProt bool `json:"secret_scanning_push_protection"`
}

type securityAnalysis struct {
	SecretScanning struct {
		Status string `json:"status"`
	} `json:"secret_scanning"`
	SecretScanningPushProtection struct {
		Status string `json:"status"`
	} `json:"secret_scanning_push_protection"`
}

type repoSecurityResponse struct {
	SecurityAndAnalysis *securityAnalysis `json:"security_and_analysis"`
}

func (c *Client) GetSecuritySettings() (*SecuritySettings, error) {
	settings := &SecuritySettings{}

	// Check vulnerability alerts
	path := c.RepoPath("vulnerability-alerts")
	err := c.Get(path, nil)
	if err != nil {
		var httpErr *api.HTTPError
		if isHTTPError(err, http.StatusNotFound, &httpErr) {
			settings.VulnerabilityAlerts = false
		} else if isHTTPError(err, 204, &httpErr) {
			settings.VulnerabilityAlerts = true
		} else {
			// 204 means enabled but go-gh might not treat it as error
			settings.VulnerabilityAlerts = false
		}
	} else {
		settings.VulnerabilityAlerts = true
	}

	// Check automated security fixes
	asfPath := c.RepoPath("automated-security-fixes")
	var asfResp struct {
		Enabled bool `json:"enabled"`
	}
	err = c.Get(asfPath, &asfResp)
	if err != nil {
		settings.AutomatedSecurityFixes = false
	} else {
		settings.AutomatedSecurityFixes = asfResp.Enabled
	}

	// Check secret scanning via repo endpoint
	var repoResp repoSecurityResponse
	err = c.Get(c.RepoPath(), &repoResp)
	if err == nil && repoResp.SecurityAndAnalysis != nil {
		settings.SecretScanning = repoResp.SecurityAndAnalysis.SecretScanning.Status == "enabled"
		settings.SecretScanningPushProt = repoResp.SecurityAndAnalysis.SecretScanningPushProtection.Status == "enabled"
	}

	return settings, nil
}

func (c *Client) EnableVulnerabilityAlerts() error {
	path := c.RepoPath("vulnerability-alerts")
	err := c.Put(path, nil, nil)
	if err != nil {
		return fmt.Errorf("failed to enable vulnerability alerts: %w", err)
	}
	return nil
}

func (c *Client) DisableVulnerabilityAlerts() error {
	path := c.RepoPath("vulnerability-alerts")
	err := c.Delete(path, nil)
	if err != nil {
		return fmt.Errorf("failed to disable vulnerability alerts: %w", err)
	}
	return nil
}

func (c *Client) EnableAutoSecurityFixes() error {
	path := c.RepoPath("automated-security-fixes")
	err := c.Put(path, nil, nil)
	if err != nil {
		return fmt.Errorf("failed to enable automated security fixes: %w", err)
	}
	return nil
}

func (c *Client) DisableAutoSecurityFixes() error {
	path := c.RepoPath("automated-security-fixes")
	err := c.Delete(path, nil)
	if err != nil {
		return fmt.Errorf("failed to disable automated security fixes: %w", err)
	}
	return nil
}

func (c *Client) SetSecretScanning(enabled bool) error {
	status := "disabled"
	if enabled {
		status = "enabled"
	}
	body := map[string]interface{}{
		"security_and_analysis": map[string]interface{}{
			"secret_scanning": map[string]string{
				"status": status,
			},
		},
	}
	return c.Patch(c.RepoPath(), body, nil)
}

func (c *Client) SetSecretScanningPushProtection(enabled bool) error {
	status := "disabled"
	if enabled {
		status = "enabled"
	}
	body := map[string]interface{}{
		"security_and_analysis": map[string]interface{}{
			"secret_scanning_push_protection": map[string]string{
				"status": status,
			},
		},
	}
	return c.Patch(c.RepoPath(), body, nil)
}
