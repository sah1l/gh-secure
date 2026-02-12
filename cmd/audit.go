package cmd

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
	"github.com/sahilxyz/gh-secure/pkg/audit"
	"github.com/sahilxyz/gh-secure/pkg/github"
	"github.com/spf13/cobra"
)

var auditJSON bool

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Audit the security posture of a repository",
	RunE:  runAudit,
}

func init() {
	auditCmd.Flags().BoolVar(&auditJSON, "json", false, "Output as JSON")
	rootCmd.AddCommand(auditCmd)
}

func runAudit(cmd *cobra.Command, args []string) error {
	client, err := github.NewClient(repoOverride)
	if err != nil {
		return err
	}

	repoName := client.Owner() + "/" + client.RepoName()

	settings, err := client.GetRepoSettings()
	if err != nil {
		return fmt.Errorf("fetching repo settings: %w", err)
	}

	bp, _ := client.GetBranchProtection(settings.DefaultBranch)

	var rulesets []github.Ruleset
	if client.SupportsRulesets() {
		rulesets, _ = client.ListRulesets()
	}

	security, _ := client.GetSecuritySettings()

	files := make(map[string]bool)
	communityFiles := []string{"LICENSE", "CONTRIBUTING.md", "SECURITY.md", "CODE_OF_CONDUCT.md", ".github/dependabot.yml"}
	for _, f := range communityFiles {
		file, err := client.GetFile(f)
		if err == nil {
			files[f] = file.Exists
		}
	}

	report := audit.RunAudit(settings, bp, rulesets, security, files)
	report.Repo = repoName

	if auditJSON {
		return outputJSON(report)
	}

	renderAudit(report)
	return nil
}

func renderAudit(report *audit.AuditReport) {
	bold := lipgloss.NewStyle().Bold(true)
	green := lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	red := lipgloss.NewStyle().Foreground(lipgloss.Color("1"))
	yellow := lipgloss.NewStyle().Foreground(lipgloss.Color("3"))
	dim := lipgloss.NewStyle().Faint(true)

	fmt.Println()
	fmt.Printf("%s  %s\n", bold.Render("Security Audit:"), report.Repo)
	fmt.Println()

	for _, c := range report.Checks {
		var icon string
		switch {
		case c.Passed:
			icon = green.Render("✓")
		case c.Severity == audit.SeverityCritical:
			icon = red.Render("✗")
		case c.Severity == audit.SeverityWarning:
			icon = yellow.Render("!")
		default:
			icon = dim.Render("·")
		}

		fmt.Printf("  %s %s\n", icon, c.Message)
		if !c.Passed && c.Fix != "" {
			fmt.Printf("    %s\n", dim.Render(c.Fix))
		}
	}

	fmt.Println()

	scoreStyle := green
	switch report.Score {
	case "D", "F":
		scoreStyle = red
	case "B", "C":
		scoreStyle = yellow
	}

	fmt.Printf("  Score: %s  (%d/%d checks passed)\n\n",
		scoreStyle.Render(report.Score),
		report.Passed,
		report.Total,
	)
}
