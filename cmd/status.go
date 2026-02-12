package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/sahilxyz/gh-secure/pkg/github"
	"github.com/spf13/cobra"
)

var statusJSON bool

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show the security posture of a repository",
	RunE:  runStatus,
}

func init() {
	statusCmd.Flags().BoolVar(&statusJSON, "json", false, "Output as JSON")
	rootCmd.AddCommand(statusCmd)
}

type statusData struct {
	Repo             string                   `json:"repo"`
	Settings         *github.RepoSettings     `json:"settings"`
	BranchProtection *github.BranchProtection `json:"branch_protection"`
	Rulesets         []github.Ruleset         `json:"rulesets"`
	Security         *github.SecuritySettings `json:"security"`
	CommunityFiles   map[string]bool          `json:"community_files"`
}

func runStatus(cmd *cobra.Command, args []string) error {
	client, err := github.NewClient(repoOverride)
	if err != nil {
		return err
	}

	data := &statusData{
		Repo:           client.Owner() + "/" + client.RepoName(),
		CommunityFiles: make(map[string]bool),
	}

	// Fetch repo settings
	data.Settings, err = client.GetRepoSettings()
	if err != nil {
		return fmt.Errorf("fetching repo settings: %w", err)
	}

	// Fetch branch protection for default branch
	data.BranchProtection, _ = client.GetBranchProtection(data.Settings.DefaultBranch)

	// Fetch rulesets
	if client.SupportsRulesets() {
		data.Rulesets, _ = client.ListRulesets()
	}

	// Fetch security settings
	data.Security, _ = client.GetSecuritySettings()

	// Check community files
	communityFiles := []string{"LICENSE", "CONTRIBUTING.md", "SECURITY.md", "CODE_OF_CONDUCT.md", ".github/dependabot.yml", "CODEOWNERS", ".github/CODEOWNERS"}
	for _, f := range communityFiles {
		file, err := client.GetFile(f)
		if err == nil {
			data.CommunityFiles[f] = file.Exists
		}
	}

	if statusJSON {
		return outputJSON(data)
	}

	renderStatus(data)
	return nil
}

func outputJSON(data interface{}) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(data)
}

func renderStatus(data *statusData) {
	bold := lipgloss.NewStyle().Bold(true)
	green := lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	red := lipgloss.NewStyle().Foreground(lipgloss.Color("1"))
	yellow := lipgloss.NewStyle().Foreground(lipgloss.Color("3"))
	dim := lipgloss.NewStyle().Faint(true)

	check := green.Render("✓")
	cross := red.Render("✗")
	warn := yellow.Render("!")

	_ = warn // used conditionally

	fmt.Println()
	fmt.Printf("%s (%s)\n", bold.Render(data.Repo), data.Settings.Visibility)
	fmt.Println()

	// License
	if data.Settings.License != nil {
		fmt.Printf("  %s License: %s\n", check, data.Settings.License.Name)
	} else {
		fmt.Printf("  %s License: %s\n", cross, dim.Render("none"))
	}

	// Default branch
	fmt.Printf("  %s Default branch: %s\n", dim.Render("·"), data.Settings.DefaultBranch)

	// Merge strategies
	var strategies []string
	if data.Settings.AllowSquashMerge {
		strategies = append(strategies, "squash")
	}
	if data.Settings.AllowMergeCommit {
		strategies = append(strategies, "merge")
	}
	if data.Settings.AllowRebaseMerge {
		strategies = append(strategies, "rebase")
	}
	fmt.Printf("  %s Merge: %s\n", dim.Render("·"), strings.Join(strategies, ", "))

	if data.Settings.DeleteBranchOnMerge {
		fmt.Printf("  %s Delete branch on merge\n", check)
	} else {
		fmt.Printf("  %s Delete branch on merge\n", cross)
	}

	fmt.Println()

	// Branch Protection
	fmt.Printf("  %s\n", bold.Render("Branch Protection"))
	if data.BranchProtection != nil {
		bp := data.BranchProtection
		fmt.Printf("    %s %s: protected\n", check, data.Settings.DefaultBranch)
		fmt.Printf("      Reviews: %d", bp.RequiredReviews)
		if bp.DismissStaleReviews {
			fmt.Print(", dismiss stale")
		}
		if bp.RequireCodeOwners {
			fmt.Print(", require CODEOWNERS")
		}
		fmt.Println()
		if bp.EnforceAdmins {
			fmt.Printf("      %s Enforce admins\n", check)
		}
		if !bp.AllowForcePushes {
			fmt.Printf("      %s Force push blocked\n", check)
		} else {
			fmt.Printf("      %s Force push allowed\n", cross)
		}
		if bp.RequireLinearHistory {
			fmt.Printf("      %s Linear history required\n", check)
		}
		if bp.RequireSignedCommits {
			fmt.Printf("      %s Signed commits required\n", check)
		}
	} else if hasActiveRulesets(data.Rulesets) {
		fmt.Printf("    %s %s: %s\n", check, data.Settings.DefaultBranch, dim.Render("protected via rulesets"))
	} else {
		fmt.Printf("    %s %s: %s\n", cross, data.Settings.DefaultBranch, dim.Render("not protected"))
	}

	fmt.Println()

	// Rulesets
	fmt.Printf("  %s\n", bold.Render("Rulesets"))
	if len(data.Rulesets) > 0 {
		for _, rs := range data.Rulesets {
			icon := check
			if rs.Enforcement == "disabled" {
				icon = dim.Render("·")
			} else if rs.Enforcement == "evaluate" {
				icon = warn
			}
			fmt.Printf("    %s %q (%s)\n", icon, rs.Name, rs.Enforcement)
		}
	} else {
		fmt.Printf("    %s %s\n", dim.Render("·"), dim.Render("none"))
	}

	fmt.Println()

	// Security
	fmt.Printf("  %s\n", bold.Render("Security"))
	if data.Security != nil {
		printBool("    ", "Vulnerability alerts", data.Security.VulnerabilityAlerts, check, cross)
		printBool("    ", "Automated security fixes", data.Security.AutomatedSecurityFixes, check, cross)
		printBool("    ", "Secret scanning", data.Security.SecretScanning, check, cross)
		printBool("    ", "Secret scanning push protection", data.Security.SecretScanningPushProt, check, cross)
	}

	fmt.Println()

	// Community files
	fmt.Printf("  %s\n", bold.Render("Community Files"))
	for f, exists := range data.CommunityFiles {
		if exists {
			fmt.Printf("    %s %s\n", check, f)
		} else {
			fmt.Printf("    %s %s\n", cross, f)
		}
	}

	fmt.Println()
}

func printBool(prefix, label string, val bool, check, cross string) {
	if val {
		fmt.Printf("%s%s %s\n", prefix, check, label)
	} else {
		fmt.Printf("%s%s %s\n", prefix, cross, label)
	}
}

func hasActiveRulesets(rulesets []github.Ruleset) bool {
	for _, rs := range rulesets {
		if rs.Enforcement != "disabled" {
			return true
		}
	}
	return false
}
