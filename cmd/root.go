package cmd

import (
	"github.com/spf13/cobra"
	"os"
)

var rootCmd = &cobra.Command{
	Use: "honeypot [OPTIONS] COMMAND [ARG...]",
	Short: "CLI for Honeypot Management Framework",
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
