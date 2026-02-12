package cmd

import (
	"fmt"
	"os"

	"github.com/sah1l/gh-secure/pkg/config"
	gh "github.com/sah1l/gh-secure/pkg/github"
	"github.com/spf13/cobra"
)

var exportOutput string

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export repository security configuration as YAML",
	Long:  "Export the current security configuration of a repository to YAML for reuse with `gh secure import`.",
	RunE:  runExport,
}

func init() {
	exportCmd.Flags().StringVarP(&exportOutput, "output", "o", "", "Write YAML to file instead of stdout")
	rootCmd.AddCommand(exportCmd)
}

func runExport(cmd *cobra.Command, args []string) error {
	client, err := gh.NewClient(repoOverride)
	if err != nil {
		return err
	}

	repoName := client.Owner() + "/" + client.RepoName()
	fmt.Fprintf(os.Stderr, "Exporting configuration from %s...\n", repoName)

	state, err := client.GetCurrentState()
	if err != nil {
		return err
	}

	// Replace summary rulesets with detailed versions (includes rules/conditions)
	if len(state.Rulesets) > 0 {
		detailed, err := client.ListRulesetsDetailed()
		if err != nil {
			return fmt.Errorf("fetching ruleset details: %w", err)
		}
		state.Rulesets = detailed
	}

	cfg := config.StateToConfig(state)

	data, err := config.Marshal(cfg)
	if err != nil {
		return err
	}

	header := fmt.Sprintf("# gh-secure config exported from %s\n", repoName)
	output := append([]byte(header), data...)

	if exportOutput != "" {
		if err := os.WriteFile(exportOutput, output, 0644); err != nil {
			return fmt.Errorf("failed to write file: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Configuration written to %s\n", exportOutput)
	} else {
		fmt.Print(string(output))
	}

	return nil
}
