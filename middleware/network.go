package middleware

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

func DumpNetwork(stopCapture <-chan string, fileName string, network types.NetworkResource) {
	f, _ := os.Create(fileName)
	w := pcapgo.NewWriter(f)
	_ = w.WriteFileHeader(1024, layers.LinkTypeEthernet)
	defer f.Close()

	// Open the device for capturing
	interfaceName := fmt.Sprintf("br-%s", network.ID[:12])
	handle, err := pcap.OpenLive(interfaceName, 1024, false, -1*time.Second)
	if err != nil {
		fmt.Printf("Error opening device %s: %v", interfaceName, err)
		os.Exit(1)
	}
	defer handle.Close()

	var packetCount int64 = 0

	// Start processing packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case packet := <-packetSource.Packets():
			_ = w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
			packetCount++
		case message := <-stopCapture:
			if message == network.Name {
				log.Printf("stop capturing %s packet.", network.Name)
				break
			}
		default:
		}
	}
}
