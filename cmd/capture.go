package cmd


import (
	"context"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/spf13/cobra"
	"honeypot/middleware"
	"log"
	"time"
)


var captureCmd = &cobra.Command{
	Use: "capture",
	Run: func(cmd *cobra.Command, args []string) {
		log.Println("Starting capturing network traffic...")

		ctx := context.Background()
		cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
		if err != nil {
			panic(err)
		}

		managedPots := make(map[string]types.NetworkResource)
		stopCapture := make(chan string, 1)

		for {
			timer := time.NewTimer(time.Second * 5)
			networks, _ := middleware.ReadAllPotNetworks(ctx, cli)
			for _, network := range networks {
				if _, found := managedPots[network.ID]; !found {
					// new pot added
					log.Printf("new %s pot detected\n", network.Name)
					managedPots[network.ID] = network
					go middleware.DumpNetwork(stopCapture, "test.pcap", potName)
				}
			}

			for _, pot := range managedPots {
				if _, found := networks[pot.ID]; !found {
					// old pot found
					log.Printf("old %s pot detected\n", pot.Name)
					delete(managedPots, pot.ID)
					// send signal to stop capturing dump
					log.Println("send signal to stop dumping network packet.")
					stopCapture <- pot.Name
				}
			}

			<- timer.C
		}
	},
}

func init() {
	rootCmd.AddCommand(captureCmd)
}