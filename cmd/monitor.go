package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"honeypot/middleware"
	"os"
)


var monitorCmd = &cobra.Command{
	Use: "monitor",
	Run: func(cmd *cobra.Command, args []string) {
		ctx := context.Background()
		cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
		if err != nil {
			panic(err)
		}

		table, err := makeTable(ctx, cli)
		if err != nil {
			panic(err)
		}

		table.Render()
	},
}

func makeTable(context context.Context, client *client.Client) (*tablewriter.Table, error){
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Pot Name", "Container Name", "CPU %", "Memory %", "Network I/O", "Block I/O"})

	var data [][]string

	stats, err := middleware.ReadAllPotStatus(context, client)
	if err != nil {
		return &tablewriter.Table{}, err
	}

	for potName := range stats {
		var containerStat types.StatsJSON
		_ = json.NewDecoder(stats[potName].Body).Decode(&containerStat)
		// https://www.datadoghq.com/blog/how-to-collect-docker-metrics/
		rx, tx := calculateNetwork(containerStat.Networks)
		blkRead, blkWrite := calculateBlockIO(containerStat.BlkioStats)
		data = append(data, []string{
			potName,
			containerStat.Name[1:],
			fmt.Sprintf("%0.2f%%", calculateCPUPercent(containerStat.CPUStats.CPUUsage.TotalUsage, containerStat.CPUStats.SystemUsage, &containerStat)),
			fmt.Sprintf("%0.2f%%", calculateMemoryPercent(containerStat.MemoryStats)),
			fmt.Sprintf("%0.2f/%0.2f", rx, tx),
			fmt.Sprintf("%d/%d", blkRead, blkWrite),
		})
	}

	table.AppendBulk(data)
	return table, nil
}

func calculateMemoryPercent(memStats types.MemoryStats) float64 {
	var memUsage float64
	if value, isCgroup1 := memStats.Stats["total_inactive_file"]; isCgroup1 && value < memStats.Usage {
		// cgroup v1
		memUsage = float64(memStats.Usage - value)
	} else if value := memStats.Stats["inactive_file"]; value < memStats.Usage {
		// cgroup v2
		memUsage = float64(memStats.Usage - value)
	} else {
		memUsage = float64(memStats.Usage)
	}

	memLimit := float64(memStats.Limit)

	if memLimit != 0 {
		return memUsage / memLimit * 100.0
	}

	return 0

}

func calculateBlockIO(stats types.BlkioStats) (uint64, uint64) {
	var blkRead, blkWrite uint64
	for _, ioEntry := range stats.IoServiceBytesRecursive {
		if len(ioEntry.Op) == 0 {
			continue
		}

		switch ioEntry.Op[0] {
		case 'r', 'R':
			blkRead = blkRead + ioEntry.Value
		case 'w', 'W':
			blkWrite = blkWrite + ioEntry.Value
		}
	}

	return blkRead, blkWrite
}

func calculateCPUPercent(previousCPU uint64, previousSystem uint64, stats *types.StatsJSON) float64 {
	var (
		cpuPercent = 0.0
		cpuDelta = float64(stats.CPUStats.CPUUsage.TotalUsage) - float64(previousCPU)
		systemDelta = float64(stats.CPUStats.SystemUsage) - float64(previousSystem)
		onlineCPUs = float64(stats.CPUStats.OnlineCPUs)
	)

	if onlineCPUs == 0.0 {
		onlineCPUs = float64(len(stats.CPUStats.CPUUsage.PercpuUsage))
	}

	if systemDelta > 0.0 && cpuDelta > 0.0 {
		cpuPercent = (cpuDelta / systemDelta) * onlineCPUs * 100.0
	}

	return cpuPercent
}

func calculateNetwork(network map[string]types.NetworkStats) (float64, float64) {
	var rx, tx float64

	for _, value := range network {
		rx += float64(value.RxBytes)
		tx += float64(value.TxBytes)
	}

	return rx, tx
}

func init() {
	rootCmd.AddCommand(monitorCmd)
}
