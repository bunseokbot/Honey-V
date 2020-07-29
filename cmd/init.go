package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use: "init",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("initialize honeypot")
	},
}

func init() {
	rootCmd.AddCommand(initCmd)
}
