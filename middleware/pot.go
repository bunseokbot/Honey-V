package middleware

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type Pot struct {
	Name string
	Containers []types.Container
}

func writeFile(buffer io.ReadCloser, fileName string) error {
	outFile, err := os.Create(fileName)
	if err != nil {
		panic(err)
	}
	defer outFile.Close()

	_, err = io.Copy(outFile, buffer)
	return err
}

func tarRepository() (io.Reader, error) {
	var buffer bytes.Buffer
	archive := tar.NewWriter(&buffer)
	rootPath, _ := os.Getwd()

	_ = filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if info.Mode()&os.ModeSymlink == os.ModeSymlink {
			return nil
		}

		if info.IsDir() {
			return nil
		}

		header, _ := tar.FileInfoHeader(info, path)
		header.Name = strings.ReplaceAll(filepath.ToSlash(path), rootPath, "")

		data, _ := os.Open(path)
		defer data.Close()

		_ = archive.WriteHeader(header)
		_, _ = io.Copy(archive, data)

		return nil
	})

	return &buffer, nil
}

func MakeNewPot(context context.Context, client *client.Client, potName string, imageName string, potPorts []string, potDockerfile string, potEnvironments []string) (Pot, error) {
	if potName == "" {
		return Pot{}, errors.New("pot name not found")
	}

	if imageName == "" && potDockerfile == "" {
		return Pot{}, errors.New("image name or dockerfile required")
	}

	var labels = make(map[string]string)
	labels["pot.name"] = potName

	potNetwork, err := client.NetworkCreate(context, potName, types.NetworkCreate{CheckDuplicate:true, Labels: labels})
	if err != nil {
		return Pot{}, errors.New("network create failed")
	}

	if dupCheck := IsExistPotName(context, client, potName); dupCheck {
		return Pot{}, errors.New("pot name already exist")
	}

	if imageName != "" {
		_, err = client.ImagePull(context, imageName, types.ImagePullOptions{})
		if err != nil {
			return Pot{}, err
		}
	} else if potDockerfile != "" {
		contextTar, _ := tarRepository()
		imageName = fmt.Sprintf("%s:latest", potName)

		_, err := client.ImageBuild(context, contextTar, types.ImageBuildOptions{
			Context: contextTar,
			Tags: []string{imageName},
			NoCache: true,
			Dockerfile: potDockerfile,
		})

		if err != nil {
			return Pot{}, err
		}
	} else {
		return Pot{}, errors.New("image name and dockerfile not found")
	}

	var endpointsConfig = make(map[string]*network.EndpointSettings)
	endpointsConfig[potName] = &network.EndpointSettings{NetworkID: potNetwork.ID}

	exposedPorts, portBindings, err := nat.ParsePortSpecs(potPorts)
	if err != nil {
		return Pot{}, err
	}

	response, err := client.ContainerCreate(context, &container.Config{
		Image: imageName,
		Labels: labels,
		ExposedPorts: exposedPorts,
		Env: potEnvironments,
		Tty: true,
	}, &container.HostConfig{
		PortBindings: portBindings,
	}, &network.NetworkingConfig{
		EndpointsConfig: endpointsConfig,
	}, "")
	if err != nil {
		return Pot{}, err
	}

	if err := client.ContainerStart(context, response.ID, types.ContainerStartOptions{}); err != nil {
		return Pot{}, err
	}

	return Pot{
		Name: potName,
	}, nil
}

func RemoveAllPots(context context.Context, client *client.Client) bool {
	pots, err := ReadAllPots(context, client)
	if err != nil {
		return false
	}

	for _, pot := range pots {
		for _, container := range pot.Containers {
			_ = client.ContainerRemove(context, container.ID, types.ContainerRemoveOptions{Force: true})
		}
		_ = client.NetworkRemove(context, pot.Name)
	}

	return true
}

func RemovePot(context context.Context, client *client.Client, potName string) bool {
	pot, err := ReadPot(context, client, potName)
	if err != nil {
		return false
	}

	for _, container := range pot.Containers {
		err := client.ContainerRemove(context, container.ID, types.ContainerRemoveOptions{Force: true})
		if err != nil {
			return false
		}
	}

	// remove network after delete all containers
	_ = client.NetworkRemove(context, potName)

	return true
}

func ReadPot(context context.Context, client *client.Client, potName string) (Pot, error) {
	containers, err := client.ContainerList(context, types.ContainerListOptions{All: true})
	if err != nil {
		return Pot{}, err
	}

	var potContainers []types.Container

	for _, container := range containers {
		if _, contains := container.Labels["pot.name"]; contains {
			if container.Labels["pot.name"] == potName {
				potContainers = append(potContainers, container)
			}
		}
	}

	if len(potContainers) > 0 {
		return Pot{Name: potName, Containers: potContainers}, nil
	}

	return Pot{}, errors.New("pot not found")
}

func IsExistPotName(context context.Context, client *client.Client, potName string) bool {
	pots, err := ReadAllPots(context, client)
	if err != nil {
		return true
	}
	
	for _, pot := range pots {
		if pot.Name == potName {
			return true
		}
	}
	
	return false
}

func ReadAllPots(context context.Context, client *client.Client) ([]Pot, error){
	var pots []Pot
	containers, err := client.ContainerList(context, types.ContainerListOptions{All: true})
	if err != nil {
		return []Pot{{}}, err
	}

	containerMap := make(map[string][]types.Container)

	for _, container := range containers {
		if _, contains := container.Labels["pot.name"]; contains {
			potName := container.Labels["pot.name"]
			if _, found := containerMap[potName]; found {
				containerMap[potName] = append(containerMap[potName], container)
			} else {
				containerMap[potName] = []types.Container{container}
			}
		}
	}

	for key := range containerMap {
		pots = append(pots, Pot{Name: key, Containers: containerMap[key]})
	}

	return pots, nil
}

func ReadAllPotStatus(context context.Context, client *client.Client) (map[string]types.ContainerStats, error) {
	potStatusMap := make(map[string]types.ContainerStats)
	pots, err := ReadAllPots(context, client)
	if err != nil {
		return potStatusMap, err
	}

	for _, pot := range pots {
		for _, container := range pot.Containers {
			stats, _ := client.ContainerStats(context, container.ID, false)
			potStatusMap[pot.Name] = stats
		}
	}

	return potStatusMap, nil
}

func ReadPotStatus(context context.Context, client *client.Client, potName string) (types.ContainerStats, error) {
	pot, err := ReadPot(context, client, potName)
	if err != nil {
		return types.ContainerStats{}, err
	}

	for _, container := range pot.Containers {
		stats, err := client.ContainerStats(context, container.ID, false)
		return stats, err
	}

	return types.ContainerStats{}, err
}

func ReadAllPotNetworks(context context.Context, client *client.Client) (map[string]types.NetworkResource, error){
	networks, err := client.NetworkList(context, types.NetworkListOptions{})
	if err != nil {
		return nil, err
	}

	potNetworks := make(map[string]types.NetworkResource)

	for _, network := range networks {
		if _, found := network.Labels["pot.name"]; found {
			potNetworks[network.ID] = network
		}
	}

	return potNetworks, nil
}

func RestartCleanPot(context context.Context, client *client.Client, prevContainer types.Container, pot Pot) error {
	var potNetwork = prevContainer.NetworkSettings.Networks[pot.Name]

	var endpointsConfig = make(map[string]*network.EndpointSettings)
	endpointsConfig[pot.Name] = &network.EndpointSettings{NetworkID: potNetwork.NetworkID}

	var potPorts []string
	for _, portMapping := range prevContainer.Ports {
		port := fmt.Sprintf("%d:%d", portMapping.PublicPort, portMapping.PrivatePort)
		potPorts = append(potPorts, port)
	}

	exposedPorts, portBindings, err := nat.ParsePortSpecs(potPorts)
	if err != nil {
		return err
	}

	response, err := client.ContainerCreate(context,
		&container.Config{
			Image:        prevContainer.Image,
			Labels:       prevContainer.Labels,
			ExposedPorts: exposedPorts,
			Tty:          true,
		},
		&container.HostConfig{
			PortBindings: portBindings,
		},
		&network.NetworkingConfig{
			EndpointsConfig: prevContainer.NetworkSettings.Networks,
		},
		"",
	)
	if err != nil {
		return err
	}

	err = client.ContainerRemove(context, prevContainer.ID, types.ContainerRemoveOptions{Force: true})
	if err != nil {
		return err
	}

	err = client.ContainerStart(context, response.ID, types.ContainerStartOptions{})
	return err
}

func CollectContainerLog(context context.Context, client *client.Client, containerId string, fileName string) error {
	responseBody, err := client.ContainerLogs(context, containerId, types.ContainerLogsOptions{
		ShowStdout: true,
		ShowStderr: true,
	})

	err = writeFile(responseBody, fileName)
	return err
}

func CollectContainerDiff(context context.Context, client *client.Client, containerId string, fileName string) error {
	diff, err := client.ContainerDiff(context, containerId)
	if err != nil {
		return err
	}

	var values []string

	for _, event := range diff {
		var path string
		if event.Kind == 0 {
			path = fmt.Sprintf("C %s", event.Path)
		} else if event.Kind == 1 {
			path = fmt.Sprintf("A %s", event.Path)
		}

		values = append(values, path)
	}

	file, err := os.Create(fileName)
	if err != nil {
		return err
	}

	_, err = file.WriteString(strings.Join(values, "\n"))
	return err
}

func CollectContainerDump(context context.Context, client *client.Client, containerId string, fileName string) error {
	commit, err := client.ContainerCommit(context, containerId, types.ContainerCommitOptions{})
	if err != nil {
		return err
	}

	dump, _ := client.ImageSave(context, []string{commit.ID})
	err = writeFile(dump, fileName)
	return err
}
