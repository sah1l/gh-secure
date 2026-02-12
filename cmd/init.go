package cmd

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
	"github.com/sahilxyz/gh-secure/pkg/config"
	gh "github.com/sahilxyz/gh-secure/pkg/github"
	"github.com/sahilxyz/gh-secure/pkg/templates"
	"github.com/sahilxyz/gh-secure/pkg/wizard"
	"github.com/spf13/cobra"
)

var (
	initPreset string
	initForce  bool
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Configure security settings for a repository",
	Long:  "Interactively configure or apply a preset security configuration to your repository.",
	RunE:  runInit,
}

func init() {
	initCmd.Flags().StringVar(&initPreset, "preset", "", "Apply a preset (oss, private, strict)")
	initCmd.Flags().BoolVar(&initForce, "force", false, "Reset existing settings before applying")
	rootCmd.AddCommand(initCmd)
}

func runInit(cmd *cobra.Command, args []string) error {
	client, err := gh.NewClient(repoOverride)
	if err != nil {
		return err
	}

	repoName := client.Owner() + "/" + client.RepoName()
	bold := lipgloss.NewStyle().Bold(true)

	fmt.Printf("\n%s %s\n\n", bold.Render("Configuring"), repoName)

	// Get current settings
	settings, err := client.GetRepoSettings()
	if err != nil {
		return fmt.Errorf("fetching repo settings: %w", err)
	}

	var cfg *config.Config

	if initPreset != "" {
		preset, ok := config.GetPreset(initPreset)
		if !ok {
			return fmt.Errorf("unknown preset %q (available: %s)", initPreset, strings.Join(config.PresetNames(), ", "))
		}
		cfg = &preset
		fmt.Printf("Using preset: %s\n\n", bold.Render(initPreset))
	} else {
		cfg, err = wizard.RunWizard()
		if err != nil {
			return fmt.Errorf("wizard cancelled: %w", err)
		}
	}

	// Show summary and confirm
	fmt.Println()
	renderConfigSummary(cfg)

	var confirm bool
	confirmForm := huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().
				Title("Apply these settings?").
				Value(&confirm),
		),
	)
	if err := confirmForm.Run(); err != nil {
		return err
	}
	if !confirm {
		fmt.Println("Aborted.")
		return nil
	}

	fmt.Println()

	// Apply settings
	return applyConfig(client, cfg, settings)
}

func renderConfigSummary(cfg *config.Config) {
	bold := lipgloss.NewStyle().Bold(true)
	dim := lipgloss.NewStyle().Faint(true)

	fmt.Printf("%s\n\n", bold.Render("Configuration Summary"))

	if cfg.Visibility != "" {
		fmt.Printf("  Visibility:       %s\n", cfg.Visibility)
	}
	if cfg.License != "" {
		fmt.Printf("  License:          %s\n", cfg.License)
	}

	// Merge strategy
	var strategies []string
	if cfg.MergeStrategy.AllowSquash {
		strategies = append(strategies, "squash")
	}
	if cfg.MergeStrategy.AllowMerge {
		strategies = append(strategies, "merge")
	}
	if cfg.MergeStrategy.AllowRebase {
		strategies = append(strategies, "rebase")
	}
	if len(strategies) > 0 {
		fmt.Printf("  Merge:            %s\n", strings.Join(strategies, ", "))
	}
	fmt.Printf("  Delete on merge:  %v\n", cfg.DeleteBranchOnMerge)

	// Rulesets / branch protection
	if len(cfg.Rulesets) > 0 {
		fmt.Printf("\n  %s\n", bold.Render("Rulesets"))
		for _, rs := range cfg.Rulesets {
			fmt.Printf("    %s → %s\n", rs.Name, strings.Join(rs.Branches, ", "))
			if rs.RequiredReviews > 0 {
				fmt.Printf("      Reviews: %d\n", rs.RequiredReviews)
			}
		}
	}
	if cfg.BranchProtection != nil {
		fmt.Printf("\n  %s\n", bold.Render("Branch Protection (legacy)"))
		fmt.Printf("    Reviews: %d\n", cfg.BranchProtection.RequiredReviews)
	}

	// Security
	fmt.Printf("\n  %s\n", bold.Render("Security"))
	fmt.Printf("    Vulnerability alerts:    %v\n", cfg.Security.VulnerabilityAlerts)
	fmt.Printf("    Auto security fixes:     %v\n", cfg.Security.AutomatedSecurityFixes)
	fmt.Printf("    Secret scanning:         %v\n", cfg.Security.SecretScanning)
	fmt.Printf("    Push protection:         %v\n", cfg.Security.SecretScanningPushProt)
	fmt.Printf("    Dependabot config:       %v\n", cfg.Security.DependabotConfig)

	// Files
	if len(cfg.Files) > 0 {
		fmt.Printf("\n  %s\n", bold.Render("Community Files"))
		for _, f := range cfg.Files {
			fmt.Printf("    %s\n", f)
		}
	}

	_ = dim
	fmt.Println()
}

func applyConfig(client *gh.Client, cfg *config.Config, current *gh.RepoSettings) error {
	green := lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	red := lipgloss.NewStyle().Foreground(lipgloss.Color("1"))
	ok := func(msg string) { fmt.Printf("  %s %s\n", green.Render("✓"), msg) }
	fail := func(msg string, err error) { fmt.Printf("  %s %s: %s\n", red.Render("✗"), msg, err) }

	// 1. Visibility
	if cfg.Visibility != "" && cfg.Visibility != current.Visibility {
		if err := client.SetVisibility(cfg.Visibility); err != nil {
			fail("Set visibility", err)
		} else {
			ok("Set visibility to " + cfg.Visibility)
		}
	}

	// 2. Merge strategies
	if err := client.SetMergeStrategies(cfg.MergeStrategy.AllowSquash, cfg.MergeStrategy.AllowMerge, cfg.MergeStrategy.AllowRebase); err != nil {
		fail("Set merge strategies", err)
	} else {
		ok("Configured merge strategies")
	}

	// 3. Delete branch on merge
	if err := client.SetDeleteBranchOnMerge(cfg.DeleteBranchOnMerge); err != nil {
		fail("Set delete branch on merge", err)
	} else {
		ok("Set delete branch on merge")
	}

	// 4. Rulesets or branch protection
	defaultBranch := current.DefaultBranch
	if len(cfg.Rulesets) > 0 {
		useRulesets := client.SupportsRulesets()
		if useRulesets {
			for _, rsCfg := range cfg.Rulesets {
				branches := rsCfg.Branches
				for i, b := range branches {
					if b == "~DEFAULT_BRANCH~" {
						branches[i] = defaultBranch
					}
				}

				rs := gh.BuildProtectionRuleset(
					rsCfg.Name,
					branches[0],
					rsCfg.RequiredReviews,
					rsCfg.DismissStaleReviews,
					rsCfg.RequireCodeOwners,
					rsCfg.RequireLinearHistory,
					rsCfg.RequireSignedCommits,
				)
				if err := client.CreateRuleset(rs); err != nil {
					fail("Create ruleset "+rsCfg.Name, err)
				} else {
					ok("Created ruleset: " + rsCfg.Name)
				}
			}
		} else {
			// Fallback to branch protection
			for _, rsCfg := range cfg.Rulesets {
				branch := defaultBranch
				if len(rsCfg.Branches) > 0 && rsCfg.Branches[0] != "~DEFAULT_BRANCH~" {
					branch = rsCfg.Branches[0]
				}
				bp := &gh.BranchProtection{
					RequiredReviews:      rsCfg.RequiredReviews,
					DismissStaleReviews:  rsCfg.DismissStaleReviews,
					RequireCodeOwners:    rsCfg.RequireCodeOwners,
					EnforceAdmins:        true,
					AllowForcePushes:     !rsCfg.PreventForcePush,
					AllowDeletions:       !rsCfg.PreventDeletion,
					RequireLinearHistory: rsCfg.RequireLinearHistory,
					RequireSignedCommits: rsCfg.RequireSignedCommits,
				}
				if err := client.SetBranchProtection(branch, bp); err != nil {
					fail("Set branch protection for "+branch, err)
				} else {
					ok("Set branch protection for " + branch + " (rulesets not available, used legacy)")
				}
			}
		}
	}

	if cfg.BranchProtection != nil {
		bp := &gh.BranchProtection{
			RequiredReviews:      cfg.BranchProtection.RequiredReviews,
			DismissStaleReviews:  cfg.BranchProtection.DismissStaleReviews,
			RequireCodeOwners:    cfg.BranchProtection.RequireCodeOwners,
			RequiredStatusChecks: cfg.BranchProtection.RequiredStatusChecks,
			StrictStatusChecks:   cfg.BranchProtection.StrictStatusChecks,
			EnforceAdmins:        cfg.BranchProtection.EnforceAdmins,
			AllowForcePushes:     cfg.BranchProtection.AllowForcePushes,
			AllowDeletions:       cfg.BranchProtection.AllowDeletions,
			RequireLinearHistory: cfg.BranchProtection.RequireLinearHistory,
			RequireSignedCommits: cfg.BranchProtection.RequireSignedCommits,
		}
		if err := client.SetBranchProtection(defaultBranch, bp); err != nil {
			fail("Set branch protection", err)
		} else {
			ok("Set branch protection for " + defaultBranch)
		}
	}

	// 5. Security features
	if cfg.Security.VulnerabilityAlerts {
		if err := client.EnableVulnerabilityAlerts(); err != nil {
			fail("Enable vulnerability alerts", err)
		} else {
			ok("Enabled vulnerability alerts")
		}
	}

	if cfg.Security.AutomatedSecurityFixes {
		if err := client.EnableAutoSecurityFixes(); err != nil {
			fail("Enable automated security fixes", err)
		} else {
			ok("Enabled automated security fixes")
		}
	}

	if cfg.Security.SecretScanning {
		if err := client.SetSecretScanning(true); err != nil {
			fail("Enable secret scanning", err)
		} else {
			ok("Enabled secret scanning")
		}
	}

	if cfg.Security.SecretScanningPushProt {
		if err := client.SetSecretScanningPushProtection(true); err != nil {
			fail("Enable secret scanning push protection", err)
		} else {
			ok("Enabled secret scanning push protection")
		}
	}

	// 6. Dependabot config
	if cfg.Security.DependabotConfig {
		ecosystems, _ := client.DetectEcosystems()
		var content string
		if len(ecosystems) > 0 {
			content = templates.Dependabot(ecosystems)
		} else {
			content = templates.DefaultDependabot()
		}
		if err := client.CreateOrUpdateFile(".github/dependabot.yml", "chore: configure Dependabot", content); err != nil {
			fail("Create dependabot.yml", err)
		} else {
			ok("Created .github/dependabot.yml")
		}
	}

	// 7. Community files
	owner := client.Owner()
	repoName := client.RepoName()
	for _, f := range cfg.Files {
		var content string
		switch f {
		case "CONTRIBUTING.md":
			content = templates.Contributing(repoName, owner)
		case "SECURITY.md":
			content = templates.Security(repoName, owner)
		case "CODE_OF_CONDUCT.md":
			content = templates.CodeOfConduct(repoName, owner)
		default:
			continue
		}
		if err := client.CreateOrUpdateFile(f, "docs: add "+f, content); err != nil {
			fail("Create "+f, err)
		} else {
			ok("Created " + f)
		}
	}

	// 8. License (if specified and not existing)
	if cfg.License != "" && current.License == nil {
		licenseContent := getLicenseContent(cfg.License, owner)
		if licenseContent != "" {
			if err := client.CreateOrUpdateFile("LICENSE", "docs: add LICENSE", licenseContent); err != nil {
				fail("Create LICENSE", err)
			} else {
				ok("Created LICENSE (" + cfg.License + ")")
			}
		}
	}

	fmt.Println()
	fmt.Printf("  %s\n\n", green.Render("Done! Run `gh secure status` to verify."))
	return nil
}

func getLicenseContent(license, owner string) string {
	year := "2025"
	switch license {
	case "mit":
		return fmt.Sprintf(`MIT License

Copyright (c) %s %s

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
`, year, owner)
	case "apache-2.0":
		return fmt.Sprintf(`Copyright %s %s

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
`, year, owner)
	default:
		return ""
	}
}
