package cmd

import (
	"context"
	"github.com/docker/docker/client"
	"github.com/spf13/cobra"
	"honeypot/middleware"
	"log"
)

var removeCmd = &cobra.Command{
	Use : "remove",
	Run: func(cmd *cobra.Command, args []string) {
		ctx := context.Background()
		cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
		if err != nil {
			panic(err)
		}

		if removeAllPots {
			if result := middleware.RemoveAllPots(ctx, cli); result {
				log.Println("Successfully remove all pots")
			}
		} else {
			if result := middleware.RemovePot(ctx, cli, potName); result {
				log.Printf("Successfully remove %s pot\n", potName)
			}
		}
	},
}

var (
	removeAllPots bool
)

func init() {
	rootCmd.AddCommand(removeCmd)

	removeCmd.Flags().BoolVarP(&removeAllPots, "all", "a", false, "Remove all pots")
	removeCmd.Flags().StringVarP(&potName, "name", "n", "", "name of pot")
}