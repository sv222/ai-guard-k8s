package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "ai-guard",
	Short: "Audit and harden AI inference workloads on Kubernetes (infrastructure layer, not prompts)",
}

// Execute runs the root command and returns the error so main can set the exit code.
func Execute() error {
	return rootCmd.Execute()
}
