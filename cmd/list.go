package cmd

import (
	"context"
	"os"
	"strings"

	"github.com/docker/docker/client"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"

	"github.com/bunseokbot/Honey-V/middleware"
)

var listCmd = &cobra.Command{
	Use: "list",
	Run: func(cmd *cobra.Command, args []string) {
		ctx := context.Background()
		cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
		if err != nil {
			panic(err)
		}

		pots, err := middleware.ReadAllPots(ctx, cli)
		if err != nil {
			panic(err)
		}

		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Name", "Containers", "Status", "Uptime/Downtime"})

		var data [][]string
		var status string
		var state string

		for _, pot := range pots {
			var containerNames []string
			for _, container := range pot.Containers {
				containerNames = append(containerNames, container.Names[0][1:])
				status = container.Status
				state = container.State
			}
			data = append(data, []string{pot.Name, strings.Join(containerNames, ","), state, status})
		}

		table.AppendBulk(data)
		table.Render()
	},
}

func init() {
	rootCmd.AddCommand(listCmd)
}
