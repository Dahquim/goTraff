package main

import (
	"sync"
	"time"
	"github.com/google/gopacket"
	"github.com/dahquim/goTraff/parser"
)

type TrafficAnalysis struct {
	PacketCount map[string]int `json:"packet_count"`
	UniqueIPs   map[string]int `json:"unique_ips"`
}

func displayAnalysis(mu *sync.Mutex, packetCount map[string]int, uniqueIPs map[string]int) {
    for {
        mu.Lock()
        // anyPackets := false
        mu.Unlock()
        time.Sleep(10 * time.Second) // Update every 10 seconds
    }
}

// Function to process packets
func processPacket(mu *sync.Mutex, packet gopacket.Packet, packetCount map[string]int, uniqueIPs map[string]int) {
    packetInfo := parser.ParsePacket(packet)

    if packetInfo != nil {
        mu.Lock()
        // Increment protocol count
        packetCount[packetInfo.Protocol]++

        // Increment unique source and destination IP counts
        uniqueIPs[packetInfo.SourceIP.String()]++
        uniqueIPs[packetInfo.DestinationIP.String()]++
        mu.Unlock()
    }
}