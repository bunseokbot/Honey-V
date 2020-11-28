package cmd

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/spf13/cobra"

	"github.com/bunseokbot/Honey-V/middleware"
)

func captureNetworkPacket(ctx context.Context, cli *client.Client, stopCapture chan string, resumeCapture chan string) {
	managedPots := make(map[string]types.NetworkResource)

	go manageNetworkPacketCapture(ctx, cli, stopCapture, resumeCapture)

	for {
		timer := time.NewTimer(time.Second * 5)
		networks, _ := middleware.ReadAllPotNetworks(ctx, cli)
		for _, network := range networks {
			if _, found := managedPots[network.ID]; !found {
				// new pot added
				log.Printf("new %s pot detected\n", network.Name)
				managedPots[network.ID] = network

				if _, err := os.Stat(filepath.Join(outputRoot, network.Name)); os.IsNotExist(err) {
					_ = os.Mkdir(filepath.Join(outputRoot, network.Name), os.ModePerm)
				}

				go middleware.DumpNetwork(stopCapture, filepath.Join(outputRoot, network.Name, "network.pcap"), network)
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

		<-timer.C
	}
}

func manageNetworkPacketCapture(ctx context.Context, cli *client.Client, stopCapture chan string, resumeCapture chan string) {
	for {
		select {
		case message := <-resumeCapture:
			log.Printf("resume %s network packet capture", message)
			network, err := middleware.ReadPotNetwork(ctx, cli, message)
			if err != nil {
				panic(err)
			}

			if _, err := os.Stat(filepath.Join(outputRoot, message)); os.IsNotExist(err) {
				_ = os.Mkdir(filepath.Join(outputRoot, message), os.ModePerm)
			}

			go middleware.DumpNetwork(stopCapture, filepath.Join(outputRoot, message, "network.pcap"), network)
		}
	}
}

func compressArtifacts(potName string) error {
	artifactPath := filepath.Join(outputRoot, potName)
	if _, err := os.Stat(artifactPath); os.IsNotExist(err) {
		return err
	}

	tarFile, err := os.Create(filepath.Join(
		outputRoot,
		fmt.Sprintf("%s_%d.tar.gz", potName, time.Now().Unix())))
	if err != nil {
		return err
	}
	defer tarFile.Close()

	var gzipWriter *gzip.Writer

	if gzipWriter, err = gzip.NewWriterLevel(tarFile, gzip.BestCompression); err != nil {
		return err
	}
	defer gzipWriter.Close()

	tw := tar.NewWriter(gzipWriter)
	defer tw.Close()

	_ = filepath.Walk(artifactPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		header, err := tar.FileInfoHeader(info, path)
		if err != nil {
			return err
		}

		header.Name = filepath.ToSlash(path)

		// write header
		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		// write body
		data, err := os.Open(path)
		if err != nil {
			return err
		}
		if _, err := io.Copy(tw, data); err != nil {
			return err
		}

		return nil
	})

	return err
}

func renameDirectory(potName string) error {
	artifactPath := filepath.Join(outputRoot, potName)
	renamePath := filepath.Join(outputRoot, fmt.Sprintf("%s_%d", potName, time.Now().Unix()))
	err := os.Rename(artifactPath, renamePath)
	return err
}

func calculateFileHash(filePath string) error {
	fileHashMap := make(map[string]string)

	err := filepath.Walk(filePath, func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() {
			hasher := sha256.New()
			s, _ := ioutil.ReadFile(path)
			hasher.Write(s)
			fileHashMap[filepath.Base(path)] = hex.EncodeToString(hasher.Sum(nil))
		}
		return err
	})

	if err != nil {
		return err
	}

	jsonString, _ := json.Marshal(fileHashMap)
	err = ioutil.WriteFile(filepath.Join(filePath, "hash.json"), jsonString, 0644)
	return err
}

func collectContainerArtifact(ctx context.Context, cli *client.Client, stopCapture chan string, resumeCapture chan string, container types.Container, pot middleware.Pot) {
	if _, err := os.Stat(pot.Name); os.IsNotExist(err) {
		_ = os.Mkdir(filepath.Join(outputRoot, pot.Name), os.ModePerm)
	}

	// collect logs
	err := middleware.CollectContainerLog(ctx, cli, container.ID, filepath.Join(outputRoot, pot.Name, "container.log"))
	if err != nil {
		log.Println("error while collecting container log")
		panic(err)
	}

	log.Printf("Collect container stdout/stderr log from %s pot\n", pot.Name)

	// collect diff
	err = middleware.CollectContainerDiff(ctx, cli, container.ID, filepath.Join(outputRoot, pot.Name, "container.diff"))
	if err != nil {
		log.Println("error while collecting container diff")
		panic(err)
	}

	log.Printf("Collect container diff log from %s pot\n", pot.Name)

	// collect top
	err = middleware.CollectContainerTop(ctx, cli, container.ID, filepath.Join(outputRoot, pot.Name, "container.top"))
	if err != nil {
		log.Println("error while collecting container top")
		panic(err)
	}

	log.Printf("Collect container top from %s pot\n", pot.Name)

	// collect container dump
	err = middleware.CollectContainerDump(ctx, cli, container.ID, filepath.Join(outputRoot, pot.Name, "dump.tar"))
	if err != nil {
		panic(err)
	}

	log.Printf("Collect container image from %s pot\n", pot.Name)

	stopCapture <- pot.Name

	// calculate hash value
	err = calculateFileHash(filepath.Join(outputRoot, pot.Name))
	if err != nil {
		log.Println("error while calculating hash")
		panic(err)
	}

	log.Printf("Calculate hash from %s pot\n", pot.Name)

	// compress artifacts
	/* err = compressArtifacts(pot.Name)
	if err != nil {
		log.Println("error while compressing artifact")
		panic(err)
	}

	log.Printf("Compress artifact from %s pot\n", pot.Name)
	*/

	err = renameDirectory(pot.Name)
	if err != nil {
		log.Println("error while renaming directory")
		panic(err)
	}

	log.Printf("Rename directory from %s pot\n", pot.Name)

	// cleanup pot container
	err = middleware.RestartCleanPot(ctx, cli, container, pot)
	if err != nil {
		log.Println("error while restarting pot")
		panic(err)
	}

	log.Printf("Restart clean %s pot\n", pot.Name)

	_ = os.RemoveAll(filepath.Join(outputRoot, pot.Name))

	resumeCapture <- pot.Name

	log.Printf("Successfully replaced %s pot to clean container", pot.Name)
}

func manageContainerArtifact(ctx context.Context, cli *client.Client, stopCapture chan string, resumeCapture chan string) {
	pots, err := middleware.ReadAllPots(ctx, cli)
	if err != nil {
		panic(err)
	}

	log.Printf("Read %d count pot(s)", len(pots))

	for _, pot := range pots {
		for _, container := range pot.Containers {
			go collectContainerArtifact(ctx, cli, stopCapture, resumeCapture, container, pot)
		}
	}
}

var collectCmd = &cobra.Command{
	Use: "collect",
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
			collectTimer := time.NewTimer(time.Hour * time.Duration(collectInterval))
			if count > 0 {
				log.Println("Start collecting artifacts from containers...")
				manageContainerArtifact(ctx, cli, stopCapture, resumeCapture)
			}
			count++
			<-collectTimer.C
		}
	},
}

var (
	outputRoot      string
	collectInterval int
)

func init() {
	rootCmd.AddCommand(collectCmd)

	collectCmd.Flags().StringVarP(&outputRoot, "path", "p", "", "Path of artifact output")
	collectCmd.Flags().IntVarP(&collectInterval, "interval", "i", 1, "Interval of artifact collection")

	collectCmd.MarkFlagRequired("path")
}
