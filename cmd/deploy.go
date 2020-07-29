package cmd

import (
	"context"
	"github.com/docker/docker/client"
	"github.com/spf13/cobra"
	"honeypot/middleware"
	"log"
	"os"
)

var deployCmd = &cobra.Command{
	Use: "deploy",
	Run: func(cmd *cobra.Command, args []string) {
		ctx := context.Background()
		cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
		if err != nil {
			panic(err)
		}

		if potComposeFile != "" {
			// compose mode

		} else if potImage == "" {
			// single mode and if pot image is empty
			log.Println("pot name is empty. terminating program")
			os.Exit(1)

		} else {
			log.Printf("Generating %s pot...", potName)
			response, err := middleware.MakeNewPot(ctx, cli, potName, potImage, potPorts)
			if err != nil {
				panic(err)
			}

			log.Printf("Successfully generated %s pot\n", potName)
			log.Printf("Pot Name: %s\n", response.Name)
			for _, container := range response.Containers {
				log.Printf("[%s] Contaier Name: %s", container.ID, container.Names[0])
			}
		}
	},
}

var (
	potName string				// Name of pot (required)
	potImage string				// Name of docker base image if you want to deploy pot as single mode (optional)
	potPorts []string			// Port forwarding mapper (optional)
	potComposeFile string		// Path of docker-compose.yml file if you want to deploy pot as compose mode (optional)
)

func init() {
	rootCmd.AddCommand(deployCmd)

	deployCmd.Flags().StringVarP(&potName, "name", "n", "", "Name of pot")
	deployCmd.Flags().StringVarP(&potImage, "image", "i", "", "Name of pot image")
	deployCmd.Flags().StringArrayVarP(&potPorts, "ports", "p", []string{}, "Port forwarding options")
	deployCmd.Flags().StringVarP(&potComposeFile, "compose", "c", "", "Path of docker-compose.yml")

	deployCmd.MarkFlagRequired("name")
}
