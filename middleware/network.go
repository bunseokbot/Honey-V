package middleware

import (
	"fmt"
	"github.com/docker/docker/api/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"log"
	"os"
	"time"
)

func DumpNetwork(stopCapture <-chan string, fileName string, network types.NetworkResource) {
	defer func() {
		f, _ := os.Create(fileName)
		w := pcapgo.NewWriter(f)
		_ = w.WriteFileHeader(1024, layers.LinkTypeEthernet)
		defer f.Close()

		// Open the device for capturing
		handle, err := pcap.OpenLive("en0", 1024, false, -1 * time.Second)
		if err != nil {
			fmt.Printf("Error opening device %s: %v", fmt.Sprintf("br-%s", network.ID[:12]), err)
			os.Exit(1)
		}
		defer handle.Close()

		var packetCount int64 = 0

		// Start processing packets
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			// Process packet here
			// fmt.Println(packet)
			_ = w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
			packetCount++

			select {
			case message := <-stopCapture:
				log.Println("message from stopCapture", message)
				if message == network.Name {
					log.Println("stop capturing packet.")
					break
				}
			default:
			}
		}
	}()
}