package main

import (
    "fmt"
    "log"
    "os"
    "sync"
    "time"
    "net"
    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
    "trafanal/parser"
)

func main() {
    selectInterface := selectInterface()

    handle, err := pcap.OpenLive(selectInterface, 1600, true, pcap.BlockForever)
    if err != nil {
        log.Fatal(err)
    }
    defer handle.Close()
   
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

    var mu sync.Mutex
    packetCount := make(map[string]int)
    uniqueIPs := make(map[string]int)

    go displayAnalysis(&mu, packetCount, uniqueIPs)

    for packet := range packetSource.Packets() {
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
}

func selectInterface() string {
    interfaces, err := net.Interfaces()
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("Select an interface:")
    for i, iface := range interfaces {
        fmt.Printf(" %d: %s\n", i, iface.Name)
    }

    fmt.Print("Select an interface to monitor (number): ")
    var choice int
    _, err = fmt.Scan(&choice)
    if err != nil || choice < 0 || choice >= len(interfaces) {
        log.Fatal(err)
        os.Exit(1)
    }

    return interfaces[choice].Name
}

func displayAnalysis(mu *sync.Mutex, packetCount map[string]int, uniqueIPs map[string]int) {
    for {
        mu.Lock()
        fmt.Print("\033[H\033[2J") // Clear the terminal
        fmt.Println("Traffic Analysis:")
        fmt.Println("Packet counts by protocol:")
        anyPackets := false

        for proto, count := range packetCount {
            fmt.Printf(" - %s: %d packets\n", proto, count)
            if count > 0 {
                anyPackets = true
            }
        }

        fmt.Println("Unique IPs:")
        for ip, count := range uniqueIPs {
            fmt.Printf(" - %s: %d packets\n", ip, count)
            if count > 0 {
                anyPackets = true
            }
        }

        if !anyPackets {
            fmt.Println("No packets captured in the last interval.")
        }

        mu.Unlock()
        time.Sleep(10 * time.Second) // Update every 10 seconds
    }
}