package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var repoOverride string

var rootCmd = &cobra.Command{
	Use:     "gh-secure",
	Short:   "Harden any GitHub repository in under 60 seconds",
	Long:    "gh-secure audits and applies security best practices to your GitHub repositories — branch protection, rulesets, merge strategies, secret scanning, and more.",
	Version: "0.1.0",
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&repoOverride, "repo", "", "Target repository in owner/name format (defaults to current git repo)")
}
