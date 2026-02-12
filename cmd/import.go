package cmd

import (
	"fmt"
	"os"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
	"github.com/sah1l/gh-secure/pkg/config"
	gh "github.com/sah1l/gh-secure/pkg/github"
	"github.com/spf13/cobra"
)

var (
	importFile string
	importYes  bool
)

var importCmd = &cobra.Command{
	Use:   "import",
	Short: "Import and apply a security configuration from a YAML file",
	Long:  "Apply a previously exported security configuration to a repository. Use --yes to skip all prompts.",
	RunE:  runImport,
}

func init() {
	importCmd.Flags().StringVarP(&importFile, "file", "f", "", "Path to YAML config file (required)")
	importCmd.Flags().BoolVarP(&importYes, "yes", "y", false, "Skip all confirmation prompts")
	_ = importCmd.MarkFlagRequired("file")
	rootCmd.AddCommand(importCmd)
}

func runImport(cmd *cobra.Command, args []string) error {
	data, err := os.ReadFile(importFile)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	cfg, err := config.Unmarshal(data)
	if err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	// Validate
	if cfg.Visibility != "" && cfg.Visibility != "public" && cfg.Visibility != "private" && cfg.Visibility != "internal" {
		return fmt.Errorf("invalid visibility %q (must be public, private, or internal)", cfg.Visibility)
	}
	if !cfg.MergeStrategy.AllowSquash && !cfg.MergeStrategy.AllowMerge && !cfg.MergeStrategy.AllowRebase {
		return fmt.Errorf("at least one merge strategy must be enabled")
	}
	for _, rs := range cfg.Rulesets {
		if rs.Name == "" {
			return fmt.Errorf("all rulesets must have a name")
		}
	}

	client, err := gh.NewClient(repoOverride)
	if err != nil {
		return err
	}

	repoName := client.Owner() + "/" + client.RepoName()
	bold := lipgloss.NewStyle().Bold(true)

	fmt.Printf("\n%s %s from %s\n\n", bold.Render("Importing to"), repoName, importFile)

	current, err := client.GetCurrentState()
	if err != nil {
		return err
	}

	renderConfigSummary(cfg, current.Settings.DefaultBranch)

	if !importYes {
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
	}

	fmt.Println()

	// Apply settings (visibility, merge, rulesets, security)
	if err := applyConfig(client, cfg, current); err != nil {
		return err
	}

	// Apply files with overwrite prompts
	if err := applyFiles(client, cfg, current, FileApplyOptions{
		PromptOverwrite: true,
		SkipConfirm:     importYes,
	}); err != nil {
		return err
	}

	green := lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	fmt.Println()
	fmt.Printf("  %s\n\n", green.Render("Done! Run `gh secure status` to verify."))
	return nil
}
