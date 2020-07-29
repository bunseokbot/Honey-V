package cmd

import (
	"context"
	"github.com/docker/docker/client"
	"github.com/spf13/cobra"
	"honeypot/middleware"
	"log"
)


var collectCmd = &cobra.Command{
	Use: "collect",
	Run: func(cmd *cobra.Command, args []string) {
		log.Println("Start collecting artifacts from containers...")

		ctx := context.Background()
		cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
		if err != nil {
			panic(err)
		}

		pots, err := middleware.ReadAllPots(ctx, cli)
		for _, pot := range pots {
			for _, container := range pot.Containers {
				log.Println(pot.Name, container.Names[0][1:])
				// collect logs
				err := middleware.CollectContainerLog(ctx, cli, container.ID, "container.log")
				if err != nil {
					panic(err)
				}

				log.Printf("Collect container stdout/stderr log from %s pot\n", container.Labels["pot.name"])

				// collect diff
				err = middleware.CollectContainerDiff(ctx, cli, container.ID, "container.diff")
				if err != nil {
					panic(err)
				}

				log.Printf("Collect container diff log from %s pot\n", container.Labels["pot.name"])

				// collect container dump
				err = middleware.CollectContainerDump(ctx, cli, container.ID, "dump.tar")
				if err != nil {
					panic(err)
				}

				log.Printf("Collect container image from %s pot\n", container.Labels["pot.name"])

				// cleanup pot container
				err = middleware.RestartCleanPot(ctx, cli, container, pot)
				if err != nil {
					panic(err)
				}

				log.Printf("Successfully replaced to clean container")
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(collectCmd)
}