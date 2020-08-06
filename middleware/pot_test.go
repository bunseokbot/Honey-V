package middleware

import (
	"context"
	"encoding/json"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"math/rand"
	"os"
	"testing"
)

const (
	letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

var (
	potName = randStringBytes(10)
)

func randStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func getDockerEnv(t *testing.T) (context.Context, *client.Client, error) {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, nil, err
	}

	return ctx, cli, err
}

func TestMakeNewPot(t *testing.T) {
	ctx, cli, err := getDockerEnv(t)
	if err != nil {
		t.Error("fail to retrieve docker environment")
	}

	pot, err := MakeNewPot(ctx, cli, potName, "nginx:latest", []string{}, "", []string{})
	if err != nil {
		t.Errorf("error while creating pot: %s", err)
	}

	if pot.Name != potName {
		t.Errorf("pot name not match\nexpected: %s, actual: %s", potName, pot.Name)
	}
}

func TestReadAllPots(t *testing.T) {
	ctx, cli, err := getDockerEnv(t)
	if err != nil {
		t.Error("fail to retrieve docker environment")
	}

	pots, err := ReadAllPots(ctx, cli)
	if err != nil {
		t.Errorf("error while reading pots: %s", err)
	}

	if len(pots) == 0 {
		t.Errorf("cannot found any pots in server")
	}

	t.Logf("found %d pot(s) in server", len(pots))
}

func TestIsExistPotName(t *testing.T) {
	ctx, cli, err := getDockerEnv(t)
	if err != nil {
		t.Error("fail to retrieve docker environment")
	}

	pot := IsExistPotName(ctx, cli, potName)
	if pot == false {
		t.Errorf("%s pot not found", potName)
	}

	t.Logf("%s pot found", potName)
}

func TestReadPot(t *testing.T) {
	ctx, cli, err := getDockerEnv(t)
	if err != nil {
		t.Error("fail to retrieve docker environment")
	}

	pot, err := ReadPot(ctx, cli, potName)
	if err != nil {
		t.Errorf("failed to read pot information: %s", err)
	}

	if pot.Name != potName {
		t.Errorf("error while reading pot information\nexpected: %s, actual: %s", potName, pot.Name)
	}

	t.Logf("pot name: %s", pot.Name)
	t.Logf("amount of containers: %d", len(pot.Containers))
}

func TestReadPotStatus(t *testing.T) {
	ctx, cli, err := getDockerEnv(t)
	if err != nil {
		t.Error("fail to retrieve docker environment")
	}

	status, err := ReadPotStatus(ctx, cli, potName)
	if err != nil {
		t.Errorf("failed to read %s pot", potName)
	}

	var containerStat types.StatsJSON
	err = json.NewDecoder(status.Body).Decode(&containerStat)
	if err != nil {
		t.Errorf("error while reading container stat - %s", err)
	}

	t.Logf("container name: %s", containerStat.Name)
	t.Logf("running processes: %d", containerStat.NumProcs)
}

func TestCollectContainerDiff(t *testing.T) {
	ctx, cli, err := getDockerEnv(t)
	if err != nil {
		t.Error("fail to retrieve docker environment")
	}

	pot, err := ReadPot(ctx, cli, potName)
	if err != nil {
		t.Errorf("error while reading pot information - %s", err)
	}

	fileName := "tmp.container.diff"
	err = CollectContainerDiff(ctx, cli, pot.Containers[0].ID, fileName)
	if err != nil {
		t.Errorf("error while collecting container diff log - %s", err)
	}

	if info, err := os.Stat(fileName); os.IsNotExist(err) {
		t.Errorf("container diff log not found")
	} else {
		t.Logf("successfully created container diff log - filesize: %d", info.Size())
		_ = os.Remove(fileName)
	}
}

func TestCollectContainerLog(t *testing.T) {
	ctx, cli, err := getDockerEnv(t)
	if err != nil {
		t.Error("fail to retrieve docker environment")
	}

	pot, err := ReadPot(ctx, cli, potName)
	if err != nil {
		t.Errorf("error while reading pot information - %s", err)
	}

	fileName := "tmp.container.log"
	err = CollectContainerLog(ctx, cli, pot.Containers[0].ID, fileName)
	if err != nil {
		t.Errorf("error while collecting container log - %s", err)
	}

	if info, err := os.Stat(fileName); os.IsNotExist(err) {
		t.Errorf("container log not found")
	} else {
		t.Logf("successfully created container log - filesize: %d", info.Size())
		_ = os.Remove(fileName)
	}
}

func TestCollectContainerDump(t *testing.T) {
	ctx, cli, err := getDockerEnv(t)
	if err != nil {
		t.Error("fail to retrieve docker environment")
	}

	pot, err := ReadPot(ctx, cli, potName)
	if err != nil {
		t.Errorf("error while reading pot information - %s", err)
	}

	fileName := "tmp.container.dump"
	err = CollectContainerDump(ctx, cli, pot.Containers[0].ID, fileName)
	if err != nil {
		t.Errorf("error while collecting container dump - %s", err)
	}

	if info, err := os.Stat(fileName); os.IsNotExist(err) {
		t.Errorf("container dump not found")
	} else {
		t.Logf("successfully created container dump - filesize: %d", info.Size())
		_ = os.Remove(fileName)
	}
}

func TestRestartCleanPot(t *testing.T) {
	ctx, cli, err := getDockerEnv(t)
	if err != nil {
		t.Error("fail to retrieve docker environment")
	}

	pot, err := ReadPot(ctx, cli, potName)
	if err != nil {
		t.Errorf("error while reading pot information - %s", err)
	}

	err = RestartCleanPot(ctx, cli, pot.Containers[0], pot)
	if err != nil {
		t.Errorf("error while restarting clean pot - %s", err)
	}
}

func TestRemovePot(t *testing.T) {
	ctx, cli, err := getDockerEnv(t)
	if err != nil {
		t.Error("fail to retrieve docker environment")
	}

	result := RemovePot(ctx, cli, potName)
	if result == false {
		t.Errorf("fail to remove %s pot", potName)
	}
}