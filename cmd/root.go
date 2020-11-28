package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "honeypot [OPTIONS] COMMAND [ARG...]",
	Short: "CLI for Honeypot Management Framework",
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
