package cmd

import (
	"archive/zip"
	"context"
	"fmt"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/spf13/cobra"
	"honeypot/middleware"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"
)


func captureNetworkPacket(ctx context.Context, cli *client.Client, stopCapture chan string, resumeCapture chan string) {
	managedPots := make(map[string]types.NetworkResource)

	for {
		timer := time.NewTimer(time.Second * 5)
		networks, _ := middleware.ReadAllPotNetworks(ctx, cli)
		for _, network := range networks {
			if _, found := managedPots[network.ID]; !found {
				// new pot added
				log.Printf("new %s pot detected\n", network.Name)
				managedPots[network.ID] = network

				if _, err := os.Stat(network.Name); os.IsNotExist(err) {
					_ = os.Mkdir(network.Name, os.ModePerm)
				}
				go middleware.DumpNetwork(stopCapture, filepath.Join(network.Name, "network.pcap"), potName)
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

		select {
		case message := <- resumeCapture:
			log.Println("resume capture packet")
			go middleware.DumpNetwork(stopCapture, filepath.Join(message, "network.pcap"), message)
		}

		<- timer.C
	}
}

func compressArtifacts(potName string) error {
	if _, err := os.Stat(potName); os.IsNotExist(err) {
		return err
	}

	zipFile, err := os.Create(filepath.Join(
		outputRoot,
		fmt.Sprintf("%s_%d.zip", potName, time.Now().Unix())))
	if err != nil {
		return err
	}
	defer zipFile.Close()

	archive := zip.NewWriter(zipFile)
	defer archive.Close()
	
	_ = filepath.Walk(potName, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		header.Name = filepath.Base(path)

		writer, err := archive.CreateHeader(header)
		if err != nil {
			return err
		}

		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		_, err = io.Copy(writer, file)
		return err
	})

	return err
}

func collectContainerArtifact(ctx context.Context, cli *client.Client, stopCapture chan string, resumeCapture chan string) {
	pots, err := middleware.ReadAllPots(ctx, cli)
	if err != nil {
		panic(err)
	}

	for _, pot := range pots {
		for _, container := range pot.Containers {
			if _, err := os.Stat(pot.Name); os.IsNotExist(err) {
				_ = os.Mkdir(pot.Name, os.ModePerm)
			}

			// collect logs
			err := middleware.CollectContainerLog(ctx, cli, container.ID, filepath.Join(pot.Name, "container.log"))
			if err != nil {
				panic(err)
			}

			log.Printf("Collect container stdout/stderr log from %s pot\n", container.Labels["pot.name"])

			// collect diff
			err = middleware.CollectContainerDiff(ctx, cli, container.ID, filepath.Join(pot.Name, "container.diff"))
			if err != nil {
				panic(err)
			}

			log.Printf("Collect container diff log from %s pot\n", container.Labels["pot.name"])

			// collect container dump
			err = middleware.CollectContainerDump(ctx, cli, container.ID, filepath.Join(pot.Name, "dump.tar"))
			if err != nil {
				panic(err)
			}

			log.Printf("Collect container image from %s pot\n", container.Labels["pot.name"])

			stopCapture <- pot.Name

			// compress artifacts
			err = compressArtifacts(pot.Name)
			if err != nil {
				panic(err)
			}


			// cleanup pot container
			err = middleware.RestartCleanPot(ctx, cli, container, pot)
			if err != nil {
				panic(err)
			}

			_ = os.RemoveAll(pot.Name)

			resumeCapture <- pot.Name

			log.Printf("Successfully replaced to clean container")
		}
	}
}

var collectorCmd = &cobra.Command{
	Use: "collector",
	Run: func(cmd *cobra.Command, args []string) {
		log.Println("Starting capturing network traffic...")

		ctx := context.Background()
		cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
		if err != nil {
			panic(err)
		}

		if _, err := os.Stat(outputRoot); os.IsNotExist(err) {
			_ = os.Mkdir(outputRoot, os.ModePerm)
		}

		stopCapture := make(chan string, 1)
		resumeCapture := make(chan string, 1)

		count := 0

		go captureNetworkPacket(ctx, cli, stopCapture, resumeCapture)

		for {
			collectTimer := time.NewTimer(time.Minute * 5)
			if count > 0 {
				log.Println("Start collecting artifacts from containers...")
				collectContainerArtifact(ctx, cli, stopCapture, resumeCapture)
			}
			count++
			<- collectTimer.C
		}
	},
}

var (
	outputRoot string
)

func init() {
	rootCmd.AddCommand(collectorCmd)

	collectorCmd.Flags().StringVarP(&outputRoot, "path", "p", "", "Path of artifact output")
	collectorCmd.MarkFlagRequired("path")
}