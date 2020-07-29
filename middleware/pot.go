package middleware

import (
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

func MakeNewPot(context context.Context, client *client.Client, potName string, imageName string, potPorts []string) (Pot, error) {
	if potName == "" {
		return Pot{}, errors.New("pot name not found")
	}

	if imageName == "" {
		return Pot{}, errors.New("image name not found")
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

	_, err = client.ImagePull(context, imageName, types.ImagePullOptions{})
	if err != nil {
		panic(err)
	}

	var endpointsConfig = make(map[string]*network.EndpointSettings)
	endpointsConfig[potName] = &network.EndpointSettings{NetworkID: potNetwork.ID}

	exposedPorts, portBindings, err := nat.ParsePortSpecs(potPorts)
	if err != nil {
		panic(err)
	}

	response, err := client.ContainerCreate(context, &container.Config{
		Image: imageName,
		Labels: labels,
		ExposedPorts: exposedPorts,
		Tty: true,
	}, &container.HostConfig{
		PortBindings: portBindings,
	}, &network.NetworkingConfig{
		EndpointsConfig: endpointsConfig,
	}, "")
	if err != nil {
		panic(err)
	}

	if err := client.ContainerStart(context, response.ID, types.ContainerStartOptions{}); err != nil {
		panic(err)
	}

	return Pot{
		Name: potName,
	}, nil
}

func RemoveAllPots(context context.Context, client *client.Client) bool {
	pots, err := ReadAllPots(context, client)
	if err != nil {
		panic(err)
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
		panic(err)
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
		panic(err)
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
		panic(err)
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
		panic(err)
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

func ReadAllPotNetworks(context context.Context, client *client.Client) (map[string]types.NetworkResource, error){
	networks, err := client.NetworkList(context, types.NetworkListOptions{})
	if err != nil {
		panic(err)
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
		panic(err)
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
		panic(err)
	}

	err = client.ContainerRemove(context, prevContainer.ID, types.ContainerRemoveOptions{Force: true})
	if err != nil {
		panic(err)
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
		panic(err)
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
		panic(err)
	}

	_, err = file.WriteString(strings.Join(values, "\n"))
	return err
}

func CollectContainerDump(context context.Context, client *client.Client, containerId string, fileName string) error {
	commit, err := client.ContainerCommit(context, containerId, types.ContainerCommitOptions{})
	if err != nil {
		panic(err)
	}

	dump, _ := client.ImageSave(context, []string{commit.ID})
	err = writeFile(dump, fileName)
	return err
}
