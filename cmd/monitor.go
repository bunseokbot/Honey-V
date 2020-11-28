package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"
	"github.com/spf13/cobra"

	"github.com/bunseokbot/Honey-V/middleware"
)

func calculatePotMemoryPercent(memStats types.MemoryStats) float64 {
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

func calculatePotBlockIO(stats types.BlkioStats) (uint64, uint64) {
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

func calculatePotCpuPercent(previousCPU uint64, previousSystem uint64, stats *types.StatsJSON) float64 {
	var (
		cpuPercent  = 0.0
		cpuDelta    = float64(stats.CPUStats.CPUUsage.TotalUsage) - float64(previousCPU)
		systemDelta = float64(stats.CPUStats.SystemUsage) - float64(previousSystem)
		onlineCPUs  = float64(stats.CPUStats.OnlineCPUs)
	)
	if onlineCPUs == 0.0 {
		onlineCPUs = float64(len(stats.CPUStats.CPUUsage.PercpuUsage))
	}
	if systemDelta > 0.0 && cpuDelta > 0.0 {
		cpuPercent = (cpuDelta / systemDelta) * onlineCPUs * 100.0
	}
	return cpuPercent
}

func calculatePotNetwork(network map[string]types.NetworkStats) (float64, float64) {
	var rx, tx float64
	for _, value := range network {
		rx += float64(value.RxBytes)
		tx += float64(value.TxBytes)
	}
	return rx, tx
}

func calculateHostMemoryPercent() float64 {
	var (
		Total               uint64
		Free                uint64
		MemAvailable        uint64
		Buffers             uint64
		Cached              uint64
		MemAvailableEnabled bool
		MemoryUseAmount     uint64
	)
	memStatus := map[string]*uint64{
		"MemTotal":     &Total,
		"MemFree":      &Free,
		"MemAvailable": &MemAvailable,
		"Buffers":      &Buffers,
		"Cached":       &Cached,
	}
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		log.Fatalf("/proc/meminfo does not exist. %v", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		i := strings.IndexRune(line, ':')
		if i < 0 {
			continue
		}
		fld := line[:i]
		if ptr := memStatus[fld]; ptr != nil {
			val := strings.TrimSpace(strings.TrimRight(line[i+1:], "kB"))
			if v, err := strconv.ParseUint(val, 10, 64); err == nil {
				*ptr = v
			}
			if fld == "MemAvailable" {
				MemAvailableEnabled = true
			}
		}
	}

	if MemAvailableEnabled {
		MemoryUseAmount = Total - MemAvailable
	} else {
		MemoryUseAmount = Total - Free - Buffers - Cached
	}

	// Memory Used Percent Return
	return float64(MemoryUseAmount) / float64(Total) * 100
}

func calculateHostCpuPercent() (idle, total uint64) {
	contents, err := ioutil.ReadFile("/proc/stat")
	if err != nil {
		log.Fatalf("/proc/stat does not exist. %v", err)
	}

	lines := strings.Split(string(contents), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if fields[0] == "cpu" {
			numFields := len(fields)
			for i := 1; i < numFields; i++ {
				val, err := strconv.ParseUint(fields[i], 10, 64)
				if err != nil {
					log.Fatalf("Unable to get information from /proc/meminfo %v", err)
				}
				total += val // tally up all the numbers to get total ticks
				if i == 4 {  // idle is the 5th field in the cpu line
					idle = val
				}
			}
			return
		}
	}
	return
}

func getPotsName(context context.Context, client *client.Client) ([]string, []string, []string) {

	pots, _ := middleware.ReadAllPots(context, client)
	var status string
	var state string
	var potNameList []string
	var runningTimeList []string
	var stateList []string

	for index, pot := range pots {
		var containerNames []string
		for _, container := range pot.Containers {
			containerNames = append(containerNames, container.Names[0][1:])
			status = container.Status
			state = container.State
		}
		potNameList = append(potNameList, ("[" + strconv.Itoa(index) + "]" + pot.Name))
		runningTimeList = append(runningTimeList, status)
		stateList = append(stateList, state)
	}

	return potNameList, runningTimeList, stateList
}

func PotsStatusLoad(context context.Context, client *client.Client, PotsCpu, PotsMemory, PotsNetowrk *[]string, runningCheck *bool) {

	*runningCheck = true

	stats, err := middleware.ReadAllPotStatus(context, client)
	var CpuList []string
	var MemoryList []string
	var Network []string
	if err != nil {
		log.Fatalf("middlware ReadAllPotStatus Error %v", err)
	}
	*PotsCpu = CpuList
	*PotsMemory = MemoryList
	*PotsNetowrk = Network

	for potName := range stats {
		var containerStat types.StatsJSON
		_ = json.NewDecoder(stats[potName].Body).Decode(&containerStat)
		// https://www.datadoghq.com/blog/how-to-collect-docker-metrics/
		rx, tx := calculatePotNetwork(containerStat.Networks)
		//blkRead, blkWrite := calculatePotBlockIO(containerStat.BlkioStats)

		*PotsCpu = append(*PotsCpu, fmt.Sprintf("%0.2f%%", calculatePotCpuPercent(containerStat.CPUStats.CPUUsage.TotalUsage, containerStat.CPUStats.SystemUsage, &containerStat)))
		*PotsMemory = append(*PotsMemory, fmt.Sprintf("%0.2f%%", calculatePotMemoryPercent(containerStat.MemoryStats)))
		*PotsNetowrk = append(*PotsNetowrk, fmt.Sprintf("%0.2f/%0.2f", rx, tx))
	}
	*runningCheck = false
}

func readLinesOffsetN(filename string, offset uint, n int) ([]string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return []string{""}, err
	}
	defer f.Close()
	var ret []string
	r := bufio.NewReader(f)
	for i := 0; i < n+int(offset) || n < 0; i++ {
		line, err := r.ReadString('\n')
		if err != nil {
			break
		}
		if i < int(offset) {
			continue
		}
		ret = append(ret, strings.Trim(line, "\n"))
	}
	return ret, nil
}

type calculateHostNetworkTotalStat struct {
	Name        string
	BytesSent   uint64
	BytesRecv   uint64
	PacketsSent uint64
	PacketsRecv uint64
}

func calculateHostNetworkTotal() (uint64, uint64, uint64, uint64) {
	filename := "/proc/net/dev"
	//https://studygolang.com/articles/3137
	lines, err := readLinesOffsetN(filename, 0, -1)
	if err != nil {
		log.Fatalf("/proc/net/dev does not exist. %v", err)
	}
	statlen := len(lines) - 1

	all := make([]calculateHostNetworkTotalStat, 0, statlen)

	for _, line := range lines[2:] {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		interfaceName := strings.TrimSpace(parts[0])
		if interfaceName == "" {
			continue
		}
		fields := strings.Fields(strings.TrimSpace(parts[1]))
		bytesRecv, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			log.Fatalf("Unable to get information(ByteRecv) from /proc/net/dev  %v", err)
		}
		packetsRecv, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			log.Fatalf("Unable to get information(packetsRecv) from /proc/net/dev  %v", err)

		}
		bytesSent, err := strconv.ParseUint(fields[8], 10, 64)
		if err != nil {
			log.Fatalf("Unable to get information(bytesSent) from /proc/net/dev  %v", err)
		}
		packetsSent, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			log.Fatalf("Unable to get information(packetSent) from /proc/net/dev  %v", err)
		}
		nic := calculateHostNetworkTotalStat{
			Name:        interfaceName,
			BytesRecv:   bytesRecv,
			PacketsRecv: packetsRecv,
			BytesSent:   bytesSent,
			PacketsSent: packetsSent}
		all = append(all, nic)
	}
	var (
		BytesSent   uint64
		BytesRecv   uint64
		PacketsSent uint64
		PacketsRecv uint64
	)
	for _, nic2 := range all {
		BytesRecv += nic2.BytesRecv
		PacketsRecv += nic2.PacketsRecv
		BytesSent += nic2.BytesSent
		PacketsSent += nic2.PacketsSent
	}
	return BytesRecv, PacketsRecv, BytesSent, PacketsSent
}

func makeInitDotList(n int) []float64 {
	ps := make([]float64, n)
	for i := range ps {
		ps[i] = 0
	}
	ps[220] = 100.00 // Maximum
	ps[221] = 0.00   // Minimum
	return ps
}

func drawInitUI(potNameList, runningTimeList, stateList, potsCpuList, potsMemoryList, potsNetworkList []string, MemoryGraphDot, NetWorkGrapDot1, NetWorkGrapDot2, NetWorkGrapDot3, NetWorkGrapDot4 []float64) (*widgets.Paragraph, *widgets.List, *widgets.List, *widgets.List, *widgets.List, *widgets.List, *widgets.List, *widgets.Plot, *widgets.Plot, *widgets.Plot, *widgets.Plot, *widgets.Paragraph, *widgets.Plot, *widgets.Gauge) {

	info := widgets.NewParagraph()
	info.Title = "Honey Pot Moniter"
	info.Text = "Stop : PRESS q or ESC "
	info.SetRect(0, 0, 50, 5)
	info.TextStyle.Fg = ui.ColorWhite
	info.BorderStyle.Fg = ui.ColorWhite

	DevInfo := widgets.NewParagraph()
	DevInfo.Title = "Dev Team."
	DevInfo.Text = "S.S.G _ Honey"
	DevInfo.SetRect(50, 0, 100, 5)
	DevInfo.TextStyle.Fg = ui.ColorWhite
	DevInfo.BorderStyle.Fg = ui.ColorWhite

	PotsName := widgets.NewList()
	PotsName.Title = "Pots List"
	PotsName.Rows = potNameList
	PotsName.SetRect(0, 5, 25, 15)
	PotsName.TextStyle.Fg = ui.ColorYellow
	PotsName.BorderStyle.Fg = ui.ColorBlue

	PotsRunningTime := widgets.NewList()
	PotsRunningTime.Title = "RunningAt"
	PotsRunningTime.Rows = runningTimeList
	PotsRunningTime.SetRect(25, 5, 40, 15)
	PotsRunningTime.TextStyle.Fg = ui.ColorYellow
	PotsRunningTime.BorderStyle.Fg = ui.ColorBlue

	PotsState := widgets.NewList()
	PotsState.Title = "Status"
	PotsState.Rows = stateList
	PotsState.SetRect(40, 5, 55, 15)
	PotsState.TextStyle.Fg = ui.ColorYellow
	PotsState.BorderStyle.Fg = ui.ColorBlue

	PotsCpu := widgets.NewList()
	PotsCpu.Title = "CPU"
	PotsCpu.Rows = potsCpuList
	PotsCpu.SetRect(55, 5, 70, 15)
	PotsCpu.TextStyle.Fg = ui.ColorYellow
	PotsCpu.BorderStyle.Fg = ui.ColorBlue

	PotsMem := widgets.NewList()
	PotsMem.Title = "Memory"
	PotsMem.Rows = potsMemoryList
	PotsMem.SetRect(70, 5, 85, 15)
	PotsMem.TextStyle.Fg = ui.ColorYellow
	PotsMem.BorderStyle.Fg = ui.ColorBlue

	PotsNet := widgets.NewList()
	PotsNet.Title = "Network"
	PotsNet.Rows = potsNetworkList
	PotsNet.SetRect(85, 5, 100, 15)
	PotsNet.TextStyle.Fg = ui.ColorYellow
	PotsNet.BorderStyle.Fg = ui.ColorBlue

	NetworkTraffic1 := widgets.NewPlot()
	NetworkTraffic1.Title = "Sent (Bytes)"
	NetworkTraffic1.Data = make([][]float64, 1)
	NetworkTraffic1.Data[0] = NetWorkGrapDot1
	NetworkTraffic1.SetRect(0, 15, 25, 25)
	NetworkTraffic1.BorderStyle.Fg = ui.ColorMagenta
	NetworkTraffic1.LineColors[0] = ui.ColorWhite

	NetworkTraffic2 := widgets.NewPlot()
	NetworkTraffic2.Title = "Sent (Packets)"
	NetworkTraffic2.Data = make([][]float64, 1)
	NetworkTraffic2.Data[0] = NetWorkGrapDot2
	NetworkTraffic2.SetRect(25, 15, 50, 25)
	NetworkTraffic2.BorderStyle.Fg = ui.ColorMagenta

	NetworkTraffic3 := widgets.NewPlot()
	NetworkTraffic3.Title = "Recv (Bytes)"
	NetworkTraffic3.Data = make([][]float64, 1)
	NetworkTraffic3.Data[0] = NetWorkGrapDot3
	NetworkTraffic3.SetRect(50, 15, 75, 25)
	NetworkTraffic3.BorderStyle.Fg = ui.ColorMagenta

	NetworkTraffic4 := widgets.NewPlot()
	NetworkTraffic4.Title = "Recv (Packets)"
	NetworkTraffic4.Data = make([][]float64, 1)
	NetworkTraffic4.Data[0] = NetWorkGrapDot4
	NetworkTraffic4.SetRect(75, 15, 100, 25)
	NetworkTraffic4.BorderStyle.Fg = ui.ColorMagenta

	MemoryUsed := widgets.NewPlot()
	MemoryUsed.Title = "Memory Use(%)"
	MemoryUsed.Data = make([][]float64, 1)
	MemoryUsed.Data[0] = MemoryGraphDot
	MemoryUsed.SetRect(0, 30, 100, 40)
	MemoryUsed.LineColors[0] = ui.ColorGreen

	CpuUsed := widgets.NewGauge()
	CpuUsed.Title = "CPU Use(%)"
	CpuUsed.SetRect(0, 25, 100, 30)
	CpuUsed.Percent = 100
	CpuUsed.BarColor = ui.ColorRed
	CpuUsed.TitleStyle.Fg = ui.ColorYellow
	CpuUsed.BorderStyle.Fg = ui.ColorCyan

	return info, PotsName, PotsRunningTime, PotsState, PotsCpu, PotsMem, PotsNet, NetworkTraffic1, NetworkTraffic2, NetworkTraffic3, NetworkTraffic4, DevInfo, MemoryUsed, CpuUsed
}

func showTable(context context.Context, client *client.Client) {
	if err := ui.Init(); err != nil {
		log.Fatalf("failed to initialize termui: %v", err)
	}
	defer ui.Close()

	potNameList, runningTimeList, stateList := getPotsName(context, client)
	potsCpuList := []string{"Wait...", "Loading.."}
	potsMemoryList := []string{"For...", "Loading.."}
	potsNetworkList := []string{"Seconds...", "Loading.."}

	// PotsStatusLoad Thread Running Check.
	var runningCheck = false
	go PotsStatusLoad(context, client, &potsCpuList, &potsMemoryList, &potsNetworkList, &runningCheck)

	MemoryGraphDot := makeInitDotList(222)
	NetWorkGrapDot1 := makeInitDotList(222)
	NetWorkGrapDot2 := makeInitDotList(222)
	NetWorkGrapDot3 := makeInitDotList(222)
	NetWorkGrapDot4 := makeInitDotList(222)

	var info, PotsName, PotsRunningTime, PotsState, PotsCpu, PotsMemory, PotsNetowrk, NetworkTraffic1, NetworkTraffic2, NetworkTraffic3, NetworkTraffic4, DevInfo, MemoryUsed, CpuUsed = drawInitUI(potNameList, runningTimeList, stateList, potsCpuList, potsMemoryList, potsNetworkList, MemoryGraphDot, NetWorkGrapDot1, NetWorkGrapDot2, NetWorkGrapDot3, NetWorkGrapDot4)

	// Host Network Amount Get
	NetworkSentBytesBefore, NetworkRecvBytesBefore, NetworkSentPacketBefore, NetworkRecvPacketBefore := calculateHostNetworkTotal()
	NetworkSentBytesNow, NetworkRecvBytesNow, NetworkSentPacketNow, NetworkRecvPacketNow := calculateHostNetworkTotal()
	// Host CPU Percent Get
	idleBefore, totalBefore := calculateHostCpuPercent()
	idleNow, totalNow := calculateHostCpuPercent()
	idleTicks := float64(idleNow - idleBefore)
	totalTicks := float64(totalNow - totalBefore)
	idleBefore, totalBefore = idleNow, totalNow
	cpuUsage := int(100 * (totalTicks - idleTicks) / totalTicks)

	// Memory Plot Control index
	memoryStartIndex := 0
	// Network Plot Control index
	networkStartIndex := 0

	// Change Color Control Function
	drawUpdateColor := func(count int) {
		if count%2 == 0 {
			info.TextStyle.Fg = ui.ColorRed
			DevInfo.TitleStyle.Fg = ui.ColorCyan
			NetworkTraffic1.BorderStyle.Fg = ui.ColorMagenta
			NetworkTraffic2.BorderStyle.Fg = ui.ColorMagenta
			NetworkTraffic3.BorderStyle.Fg = ui.ColorMagenta
			NetworkTraffic4.BorderStyle.Fg = ui.ColorMagenta
			MemoryUsed.BorderStyle.Fg = ui.ColorYellow
		} else {
			info.TextStyle.Fg = ui.ColorWhite
			DevInfo.TitleStyle.Fg = ui.ColorWhite
			NetworkTraffic1.BorderStyle.Fg = ui.ColorWhite
			NetworkTraffic2.BorderStyle.Fg = ui.ColorWhite
			NetworkTraffic3.BorderStyle.Fg = ui.ColorWhite
			NetworkTraffic4.BorderStyle.Fg = ui.ColorWhite
			MemoryUsed.BorderStyle.Fg = ui.ColorWhite
		}
	}

	// Change information Control Function
	draw := func(count int) {
		networkStartIndex = count % 200
		memoryStartIndex = count % 125

		if memoryStartIndex == 0 {
			copy(MemoryGraphDot[:95], MemoryGraphDot[125:220])
		}
		if networkStartIndex == 0 {
			copy(NetWorkGrapDot1[:20], NetWorkGrapDot1[200:220])
			copy(NetWorkGrapDot2[:20], NetWorkGrapDot2[200:220])
			copy(NetWorkGrapDot3[:20], NetWorkGrapDot3[200:220])
			copy(NetWorkGrapDot4[:20], NetWorkGrapDot4[200:220])
		}

		NetworkSentBytesNow, NetworkRecvBytesNow, NetworkSentPacketNow, NetworkRecvPacketNow = calculateHostNetworkTotal()
		NetWorkGrapDot1[networkStartIndex+20] = float64(NetworkSentBytesNow) - float64(NetworkSentBytesBefore)
		NetWorkGrapDot2[networkStartIndex+20] = float64(NetworkSentPacketNow) - float64(NetworkSentPacketBefore)
		NetWorkGrapDot3[networkStartIndex+20] = float64(NetworkRecvBytesNow) - float64(NetworkRecvBytesBefore)
		NetWorkGrapDot4[networkStartIndex+20] = float64(NetworkRecvPacketNow) - float64(NetworkRecvPacketBefore)
		NetworkSentBytesBefore, NetworkRecvBytesBefore, NetworkSentPacketBefore, NetworkRecvPacketBefore = NetworkSentBytesNow, NetworkRecvBytesNow, NetworkSentPacketNow, NetworkRecvPacketNow
		NetworkTraffic1.Data[0] = NetWorkGrapDot1[networkStartIndex:]
		NetworkTraffic2.Data[0] = NetWorkGrapDot2[networkStartIndex:]
		NetworkTraffic3.Data[0] = NetWorkGrapDot3[networkStartIndex:]
		NetworkTraffic4.Data[0] = NetWorkGrapDot4[networkStartIndex:]

		MemoryGraphDot[memoryStartIndex+95] = calculateHostMemoryPercent()
		MemoryUsed.Data[0] = MemoryGraphDot[memoryStartIndex:]

		PotsCpu.Rows = potsCpuList[count%len(potsCpuList):]
		PotsMemory.Rows = potsMemoryList[count%len(potsMemoryList):]
		PotsNetowrk.Rows = potsNetworkList[count%len(potsNetworkList):]
		PotsName.Rows = potNameList[count%len(potNameList):]
		PotsRunningTime.Rows = runningTimeList[count%len(runningTimeList):]
		PotsState.Rows = stateList[count%len(stateList):]

		if runningCheck == false {
			go PotsStatusLoad(context, client, &potsCpuList, &potsMemoryList, &potsNetworkList, &runningCheck)
		}

		if count%2 == 0 {
			idleNow, totalNow = calculateHostCpuPercent()
			idleTicks = float64(idleNow - idleBefore)
			totalTicks = float64(totalNow - totalBefore)
			cpuUsage = int(100 * (totalTicks - idleTicks) / totalTicks)
			CpuUsed.Percent = cpuUsage % 101
			idleBefore, totalBefore = idleNow, totalNow
		}

		NetworkTraffic1.Data[0] = NetWorkGrapDot1[networkStartIndex:]
		NetworkTraffic2.Data[0] = NetWorkGrapDot2[networkStartIndex:]
		NetworkTraffic3.Data[0] = NetWorkGrapDot3[networkStartIndex:]
		NetworkTraffic4.Data[0] = NetWorkGrapDot4[networkStartIndex:]

		ui.Render(info, PotsName, PotsCpu, PotsMemory, PotsNetowrk, PotsRunningTime, PotsState, NetworkTraffic1, NetworkTraffic2, NetworkTraffic3, NetworkTraffic4, DevInfo, MemoryUsed, CpuUsed)
	}

	tickerCount := 1
	draw(tickerCount)
	tickerCount++

	uiEvents := ui.PollEvents()
	ticker := time.NewTicker(time.Millisecond * 1000).C

	for {
		select {
		case e := <-uiEvents:
			switch e.ID {
			case "q", "<C-c>":
				return
			}
		case <-ticker:
			drawUpdateColor(tickerCount)
			draw(tickerCount)
			tickerCount++
		}
	}
}

var monitorCmd = &cobra.Command{
	Use: "monitor",
	Run: func(cmd *cobra.Command, args []string) {
		ctx := context.Background()
		cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
		if err != nil {
			panic(err)
		}
		showTable(ctx, cli)
	},
}

func init() {
	rootCmd.AddCommand(monitorCmd)
}
