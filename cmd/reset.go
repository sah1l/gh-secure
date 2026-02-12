package cmd

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
	gh "github.com/sah1l/gh-secure/pkg/github"
	"github.com/spf13/cobra"
)

var (
	resetAll        bool
	resetRules      bool
	resetProtection bool
)

var resetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Remove security settings from a repository",
	Long:  "Selectively or completely remove branch protection, rulesets, and other security settings.",
	RunE:  runReset,
}

func init() {
	resetCmd.Flags().BoolVar(&resetAll, "all", false, "Remove all security settings (requires confirmation)")
	resetCmd.Flags().BoolVar(&resetRules, "rules", false, "Remove all rulesets only")
	resetCmd.Flags().BoolVar(&resetProtection, "protection", false, "Remove branch protection only")
	rootCmd.AddCommand(resetCmd)
}

func runReset(cmd *cobra.Command, args []string) error {
	client, err := gh.NewClient(repoOverride)
	if err != nil {
		return err
	}

	repoName := client.Owner() + "/" + client.RepoName()
	bold := lipgloss.NewStyle().Bold(true)
	green := lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	red := lipgloss.NewStyle().Foreground(lipgloss.Color("1"))

	ok := func(msg string) { fmt.Printf("  %s %s\n", green.Render("✓"), msg) }
	fail := func(msg string, err error) { fmt.Printf("  %s %s: %s\n", red.Render("✗"), msg, err) }

	fmt.Printf("\n%s %s\n\n", bold.Render("Reset:"), repoName)

	if resetAll {
		// Require typing RESET
		var confirmation string
		confirmForm := huh.NewForm(
			huh.NewGroup(
				huh.NewInput().
					Title("Type RESET to confirm removal of all security settings").
					Value(&confirmation),
			),
		)
		if err := confirmForm.Run(); err != nil {
			return err
		}
		if strings.TrimSpace(confirmation) != "RESET" {
			fmt.Println("Aborted.")
			return nil
		}

		return resetEverything(client, ok, fail)
	}

	if resetRules {
		return resetRulesets(client, ok, fail)
	}

	if resetProtection {
		return resetBranchProtection(client, ok, fail)
	}

	// Interactive mode
	return resetInteractive(client, ok, fail)
}

func resetEverything(client *gh.Client, ok func(string), fail func(string, error)) error {
	fmt.Println()
	resetRulesets(client, ok, fail)
	resetBranchProtection(client, ok, fail)
	resetSecurityFeatures(client, ok, fail)
	fmt.Println()
	return nil
}

func resetRulesets(client *gh.Client, ok func(string), fail func(string, error)) error {
	rulesets, err := client.ListRulesets()
	if err != nil {
		fail("List rulesets", err)
		return nil
	}
	if len(rulesets) == 0 {
		fmt.Println("  No rulesets found.")
		return nil
	}

	for _, rs := range rulesets {
		// Need full ruleset data to get ID
		if err := client.DeleteRuleset(rs.ID); err != nil {
			fail(fmt.Sprintf("Delete ruleset %q", rs.Name), err)
		} else {
			ok(fmt.Sprintf("Deleted ruleset: %s", rs.Name))
		}
	}
	return nil
}

func resetBranchProtection(client *gh.Client, ok func(string), fail func(string, error)) error {
	branches, err := client.ListProtectedBranches()
	if err != nil {
		fail("List protected branches", err)
		return nil
	}
	if len(branches) == 0 {
		fmt.Println("  No protected branches found.")
		return nil
	}

	for _, branch := range branches {
		if err := client.DeleteBranchProtection(branch); err != nil {
			fail(fmt.Sprintf("Remove protection from %s", branch), err)
		} else {
			ok(fmt.Sprintf("Removed protection from %s", branch))
		}
	}
	return nil
}

func resetSecurityFeatures(client *gh.Client, ok func(string), fail func(string, error)) error {
	if err := client.DisableVulnerabilityAlerts(); err != nil {
		fail("Disable vulnerability alerts", err)
	} else {
		ok("Disabled vulnerability alerts")
	}

	if err := client.DisableAutoSecurityFixes(); err != nil {
		fail("Disable automated security fixes", err)
	} else {
		ok("Disabled automated security fixes")
	}

	if err := client.SetSecretScanning(false); err != nil {
		fail("Disable secret scanning", err)
	} else {
		ok("Disabled secret scanning")
	}

	if err := client.SetSecretScanningPushProtection(false); err != nil {
		fail("Disable secret scanning push protection", err)
	} else {
		ok("Disabled secret scanning push protection")
	}

	return nil
}

func resetInteractive(client *gh.Client, ok func(string), fail func(string, error)) error {
	var categories []string

	selectForm := huh.NewForm(
		huh.NewGroup(
			huh.NewMultiSelect[string]().
				Title("What do you want to reset?").
				Options(
					huh.NewOption("Rulesets", "rulesets"),
					huh.NewOption("Branch protection", "protection"),
					huh.NewOption("Security features", "security"),
				).
				Value(&categories),
		),
	)
	if err := selectForm.Run(); err != nil {
		return err
	}

	if len(categories) == 0 {
		fmt.Println("Nothing selected.")
		return nil
	}

	var confirm bool
	confirmForm := huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().
				Title(fmt.Sprintf("Reset %s?", strings.Join(categories, ", "))).
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
	for _, cat := range categories {
		switch cat {
		case "rulesets":
			resetRulesets(client, ok, fail)
		case "protection":
			resetBranchProtection(client, ok, fail)
		case "security":
			resetSecurityFeatures(client, ok, fail)
		}
	}
	fmt.Println()
	return nil
}
