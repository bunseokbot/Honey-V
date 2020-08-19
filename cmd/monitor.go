package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/spf13/cobra"
	"honeypot/middleware"
	"strings"
	"log"
	"time"
	"os"
	"bufio"
	"strconv"
	"io/ioutil"
	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"


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

func calculatePotNetwork(network map[string]types.NetworkStats) (float64, float64) {
	var rx, tx float64

	for _, value := range network {
		rx += float64(value.RxBytes)
		tx += float64(value.TxBytes)
	}

	return rx, tx
}
func calculateHostMemoryPercent() (float64) {
	var (
		Total uint64
		Free uint64
		MemAvailable uint64
		Buffers uint64
		Cached uint64
		MemAvailableEnabled bool
	)
	memStatus := map[string]*uint64{
		"MemTotal": &Total,
		"MemFree": &Free,
		"MemAvailable": &MemAvailable,
		"Buffers":&Buffers,
		"Cached": &Cached,
	}
    file, err := os.Open("/proc/meminfo")
    if err != nil {
		fmt.Println("ERROR")
    }
    defer file.Close()
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
		line :=scanner.Text()
		i :=strings.IndexRune(line,':')
		if i<0 {
			continue
		}

		fld := line[:i]
		if ptr := memStatus[fld]; ptr != nil {
			val := strings.TrimSpace(strings.TrimRight(line[i+1:], "kB"))
			if v,err := strconv.ParseUint(val,10,64); err ==nil {
				*ptr=v
			}
			if fld == "MemAvailable" {
				MemAvailableEnabled = true
			}
		}
	}
	var Use uint64
    if MemAvailableEnabled {
			 Use = Total - MemAvailable
     } else {
			 Use = Total - Free - Buffers - Cached
    }
	UsedPercent := float64(Use) / float64(Total) * 100

	return UsedPercent
}

func calculateHostCpuPercent() (idle, total uint64) {
    contents, err := ioutil.ReadFile("/proc/stat")
    if err != nil {
        return
    }
    lines := strings.Split(string(contents), "\n")
    for _, line := range(lines) {
        fields := strings.Fields(line)
        if fields[0] == "cpu" {
            numFields := len(fields)
            for i := 1; i < numFields; i++ {
                val, err := strconv.ParseUint(fields[i], 10, 64)
                if err != nil {
                    fmt.Println("Error: ", i, fields[i], err)
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


func PotDetailMod(){
				p3 := widgets.NewParagraph()
				p3.Title = "Pot Detail Monitor Mod Tmp"
				p3.Text = "Stop : PRESS q or ESC \n"
				p3.SetRect(0, 0, 50, 5)
				p3.TextStyle.Fg = ui.ColorWhite
				p3.BorderStyle.Fg = ui.ColorCyan
				ui.Render(p3)
	}


func getPotsName(context context.Context, client *client.Client) ([]string){

	pots, _ := middleware.ReadAllPots(context, client)
	var status string
	var state string
	var data []string;
	var viewName string;
	for index, pot := range pots {
			var containerNames []string
			for _, container := range pot.Containers {
				containerNames = append(containerNames, container.Names[0][1:])
				status = container.Status
				state = container.State
			}
			viewName=" ["+strconv.Itoa(index)+"]    "+pot.Name +"    "+status+"    "+state+"   "+ "Calculating..."
			data = append(data,viewName)
		}
	return data
}



func PotsStatusLoad(context context.Context, client *client.Client, data *[]string)(){
	stats, err := middleware.ReadAllPotStatus(context, client)
	var CpuList []string
	var MemoryList []string
	var NetworkList []string
	if err != nil {
		fmt.Println(CpuList,MemoryList,NetworkList)
	}
	var lineData string
	var tmpData string
	lineIndex :=0

	*data = CpuList
	for potName := range stats {
		var containerStat types.StatsJSON
		_ = json.NewDecoder(stats[potName].Body).Decode(&containerStat)
		// https://www.datadoghq.com/blog/how-to-collect-docker-metrics/
		rx, tx := calculatePotNetwork(containerStat.Networks)
		//blkRead, blkWrite := calculatePotBlockIO(containerStat.BlkioStats)
		lineData= "["+strconv.Itoa(lineIndex) +"] "

		lineData+=potName+"    "
		lineData+=containerStat.Name[1:] +"    "
		tmpData=fmt.Sprintf("%0.2f%%    ",calculatePotCpuPercent(containerStat.CPUStats.CPUUsage.TotalUsage, containerStat.CPUStats.SystemUsage, &containerStat)) 
		lineData+= tmpData 
		tmpData=fmt.Sprintf("%0.2f%%    ",calculatePotMemoryPercent(containerStat.MemoryStats))
		lineData+= tmpData
		tmpData=fmt.Sprintf("%0.2f/%0.2f",rx,tx)
		lineData+= tmpData
		*data=append(*data,lineData)
		lineIndex+=1
		}
}

//https://studygolang.com/articles/3137
type netIOCountersStat struct {
	Name        string
	BytesSent   uint64
	BytesRecv   uint64
	PacketsSent uint64
	PacketsRecv uint64
}
func readLines(filename string) ([]string, error) {
	return readLinesOffsetN(filename, 0, -1)
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

func netIOCounters() (uint64, uint64, uint64, uint64) {

	filename := "/proc/net/dev"
	lines, err := readLines(filename)
	if err != nil {
		return 1,1,1,1
	}
	statlen := len(lines) - 1

	all := make([]netIOCountersStat, 0, statlen)

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
			return 1,1,1,1
		}
		packetsRecv, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 1,1,1,1
		}
		bytesSent, err := strconv.ParseUint(fields[8], 10, 64)
		if err != nil {
			return 1,1,1,1
		}
		packetsSent, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			return 1,1,1,1
		}

		nic := netIOCountersStat{
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

func showTable(context context.Context, client *client.Client) {
	if err := ui.Init(); err != nil {
		log.Fatalf("failed to initialize termui: %v", err)
	}
	defer ui.Close()

	info := widgets.NewParagraph()
	info.Title = "Honey Pot Moniter"
	info.Text = "Stop : PRESS q or ESC \nDetail : PRESS container number"
	info.SetRect(0, 0, 50, 5)
	info.TextStyle.Fg = ui.ColorWhite
	info.BorderStyle.Fg = ui.ColorWhite

	var PotList  []string;
	PotList=getPotsName(context,client)
	go PotsStatusLoad(context,client,&PotList)
	PotsName := widgets.NewList()
	PotsName.Title = "Pots List"
	PotsName.Rows = PotList
	PotsName.SetRect(0, 5, 100, 15)
	PotsName.TextStyle.Fg = ui.ColorYellow


	MemoryGraphDot := (func() []float64 {
		n := 222 // list len
		ps := make([]float64, n)
		for i := range ps {
			ps[i] = 0
		}
		ps[220]=100.00 // Maximum
		ps[221]=0.00 // Minimum
		return ps
	})()
	NetWorkGrapDot1:= (func() []float64 {
		n := 222 // list len
		ps := make([]float64, n)
		for i := range ps {
			ps[i] = 0
		}
		return ps
	})()
	NetWorkGrapDot2:= (func() []float64 {
		n := 222 // list len
		ps := make([]float64, n)
		for i := range ps {
			ps[i] = 0
		}
		return ps
	})()

	NetWorkGrapDot3:= (func() []float64 {
		n := 222 // list len
		ps := make([]float64, n)
		for i := range ps {
			ps[i] = 0
		}
		return ps
	})()

	NetWorkGrapDot4:= (func() []float64 {
		n := 222 // list len
		ps := make([]float64, n)
		for i := range ps {
			ps[i] = 0
		}
		return ps
	})()


	BytesSentB,BytesRecvB,PacketsSentB,PacketesRecvB := netIOCounters()
	BytesSentA,BytesRecvA,PacketsSentA,PacketesRecvA := netIOCounters()


	NetworkTraffic1 := widgets.NewPlot()
	NetworkTraffic1.Title = "Sent (Bytes)"
	NetworkTraffic1.Data =make([][]float64,1)
	NetworkTraffic1.Data[0]= NetWorkGrapDot1
	NetworkTraffic1.SetRect(0,15,25,25)
	NetworkTraffic1.AxesColor= ui.ColorWhite
	NetworkTraffic1.LineColors[0] = ui.ColorCyan
	ui.Render(NetworkTraffic1)


	NetworkTraffic2 := widgets.NewPlot()
	NetworkTraffic2.Title = "Sent (Packets)"
	NetworkTraffic2.Data =make([][]float64,1)
	NetworkTraffic2.Data[0]= NetWorkGrapDot2
	NetworkTraffic2.SetRect(25,15,50,25)
	NetworkTraffic2.AxesColor= ui.ColorWhite
	NetworkTraffic2.LineColors[0]= ui.ColorCyan

	NetworkTraffic3 := widgets.NewPlot()
	NetworkTraffic3.Title = "Recv (Bytes)"
	NetworkTraffic3.Data =make([][]float64,1)
	NetworkTraffic3.Data[0]= NetWorkGrapDot3
	NetworkTraffic3.SetRect(50,15,75,25)
	NetworkTraffic3.AxesColor= ui.ColorWhite
	NetworkTraffic3.LineColors[0]= ui.ColorCyan


	NetworkTraffic4 := widgets.NewPlot()
	NetworkTraffic4.Title = "Recv (Packets)"
	NetworkTraffic4.Data =make([][]float64,1)
	NetworkTraffic4.Data[0]=  NetWorkGrapDot3
	NetworkTraffic4.SetRect(75,15,100,25)
	NetworkTraffic4.AxesColor= ui.ColorWhite
	NetworkTraffic4.LineColors[0]= ui.ColorYellow



	DevInfo := widgets.NewParagraph()
	DevInfo.Title = "Dev Team."
	DevInfo.Text = "S.S.G _ Honey"
	DevInfo.SetRect(50, 0, 100, 5)
	DevInfo.TextStyle.Fg = ui.ColorWhite
	DevInfo.BorderStyle.Fg = ui.ColorRed
	ui.Render(DevInfo)


	MemoryUsed := widgets.NewPlot()
	MemoryUsed.Title = "Memory Use"
	MemoryUsed.Data = make([][]float64, 1)
	MemoryUsed.Data[0] = MemoryGraphDot
	MemoryUsed.SetRect(0, 25, 100, 35)
	MemoryUsed.AxesColor = ui.ColorWhite
	MemoryUsed.LineColors[0] = ui.ColorYellow


    idle0, total0 := calculateHostCpuPercent()
    idle1, total1 := calculateHostCpuPercent()
	idleTicks := float64(idle1 - idle0)
	totalTicks := float64(total1 - total0)
	idle0,total0 = idle1,total1

	cpuUsage := int(100 * (totalTicks - idleTicks) / totalTicks)
	CpuUsed := widgets.NewGauge()
	CpuUsed.Title = "CPU Use"
	CpuUsed.SetRect(0,35 , 100, 40)
	CpuUsed.Percent = 100
	CpuUsed.BarColor = ui.ColorRed
	CpuUsed.BorderStyle.Fg = ui.ColorWhite
	CpuUsed.TitleStyle.Fg = ui.ColorCyan


	MemoryStartIndex :=0
	NetworkStartIndex :=0


	updateParagraph := func(count int) {
		if count%2 == 0 {
			info.TextStyle.Fg = ui.ColorRed
		} else {
			info.TextStyle.Fg = ui.ColorWhite
		}
	}

	draw := func(count int) {
		NetworkStartIndex=count%220
		MemoryStartIndex=count%125


		MemoryGraphDot[MemoryStartIndex+95]= calculateHostMemoryPercent()

		if(MemoryGraphDot[MemoryStartIndex+20] > 70){
				MemoryUsed.LineColors[0] = ui.ColorRed
		} else if(MemoryGraphDot[MemoryStartIndex+20] > 50){
				MemoryUsed.LineColors[0] = ui.ColorYellow
		} else {
				MemoryUsed.LineColors[0] = ui.ColorGreen

		}

		if MemoryStartIndex == 0{
			copy (MemoryGraphDot[:95], MemoryGraphDot[125:220])
		}

		if NetworkStartIndex == 0 {
			copy (NetWorkGrapDot1[:20],NetWorkGrapDot1[200:220])
			copy (NetWorkGrapDot2[:20],NetWorkGrapDot2[200:220])
			copy (NetWorkGrapDot3[:20],NetWorkGrapDot3[200:220])
			copy (NetWorkGrapDot4[:20],NetWorkGrapDot4[200:220])
		}
		BytesSentA,BytesRecvA,PacketsSentA,PacketesRecvA = netIOCounters()

		NetWorkGrapDot1[NetworkStartIndex+20]= float64(BytesSentA)-float64(BytesSentB);
		NetWorkGrapDot2[NetworkStartIndex+20]= float64(PacketsSentA)-float64(PacketsSentB);
		NetWorkGrapDot3[NetworkStartIndex+20]= float64(BytesRecvA)-float64(BytesRecvB);
		NetWorkGrapDot4[NetworkStartIndex+20]= float64(PacketesRecvA)-float64(PacketesRecvB);


		BytesSentB,BytesRecvB,PacketsSentB,PacketesRecvB = BytesSentA,BytesRecvA,PacketsSentA,PacketesRecvA

		if(count %2==0){
		    idle1, total1 = calculateHostCpuPercent()
		    idleTicks = float64(idle1 - idle0)
		    totalTicks = float64(total1 - total0)
		    cpuUsage = int(100 * (totalTicks - idleTicks) / totalTicks)
			CpuUsed.Percent = cpuUsage%101
			idle0,total0= idle1,total1
		}
		if(count%10 ==0){
			go PotsStatusLoad(context,client,&PotList)
		}
		PotsName.Rows =PotList[count%len(PotList):]
		MemoryUsed.Data[0] = MemoryGraphDot[MemoryStartIndex:]
		NetworkTraffic1.Data[0] = NetWorkGrapDot1 [NetworkStartIndex:]
		NetworkTraffic2.Data[0] = NetWorkGrapDot2 [NetworkStartIndex:]
		NetworkTraffic3.Data[0] = NetWorkGrapDot3 [NetworkStartIndex:]
		NetworkTraffic4.Data[0] = NetWorkGrapDot4 [NetworkStartIndex:]
		ui.Render(info, PotsName, NetworkTraffic1,NetworkTraffic2,NetworkTraffic3,NetworkTraffic4,DevInfo, MemoryUsed, CpuUsed)
	}

	detailValue := 1
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
			case "1":
				ui.Clear()
				detailValue=0
			}
		case <-ticker:
			if(detailValue == 0){
				PotDetailMod()
			}else {
				updateParagraph(tickerCount)
				draw(tickerCount)
				tickerCount++
			}
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
		showTable(ctx,cli)
	},
}

func init() {
	rootCmd.AddCommand(monitorCmd)
}
