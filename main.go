package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {
	// Find available network interfaces
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	// Use the first available interface
	if len(devices) == 0 {
		log.Fatal("No network devices found")
	}

	device := devices[0].Name
	fmt.Printf("Recording traffic on interface: %s\n", device)

	// Open device for capturing
	handle, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Create log file
	logFile, err := os.Create("traffic.log")
	if err != nil {
		log.Fatal(err)
	}
	defer logFile.Close()

	fmt.Println("Starting traffic capture... Press Ctrl+C to stop")

	// Capture packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetCount := 0

	for packet := range packetSource.Packets() {
		packetCount++
		timestamp := time.Now().Format("2006-01-02 15:04:05")
		
		// Extract basic info
		srcIP, dstIP := extractIPs(packet)
		protocol := getProtocol(packet)
		size := len(packet.Data())
		data := packet.Data()

		// Log packet info
		logEntry := fmt.Sprintf("[%s] Packet #%d | %s | %s -> %s | Size: %d bytes | Data: %x\n",
			timestamp, packetCount, protocol, srcIP, dstIP, size, data)
		
		fmt.Print(logEntry)
		logFile.WriteString(logEntry)
	}
}

func extractIPs(packet gopacket.Packet) (string, string) {
	if ipLayer := packet.NetworkLayer(); ipLayer != nil {
		src := ipLayer.NetworkFlow().Src().String()
		dst := ipLayer.NetworkFlow().Dst().String()
		return src, dst
	}
	return "unknown", "unknown"
}

func getProtocol(packet gopacket.Packet) string {
	if tcpLayer := packet.TransportLayer(); tcpLayer != nil {
		return tcpLayer.LayerType().String()
	}
	if netLayer := packet.NetworkLayer(); netLayer != nil {
		return netLayer.LayerType().String()
	}
	return "unknown"
}
