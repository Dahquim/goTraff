// main.go
package main

import (
    "log"
    "net"
    "os"
    "sync"
    "fmt"
    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
)

func selectInterface() string {
    interfaces, err := net.Interfaces()
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("Available network interfaces:")
    for i, iface := range interfaces {
        fmt.Printf("%d: %s\n", i, iface.Name)
    }

    fmt.Print("Select an interface to monitor (number): ")
    var choice int
    _, err = fmt.Scan(&choice)
    if err != nil || choice < 0 || choice >= len(interfaces) {
        fmt.Println("Invalid selection. Exiting.")
        os.Exit(1)
    }

    return interfaces[choice].Name
}

func main() {
    selectedInterface := selectInterface() // Get user-selected interface

    handle, err := pcap.OpenLive(selectedInterface, 1600, true, pcap.BlockForever)
    if err != nil {
        log.Fatal(err)
    }
    defer handle.Close()

    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

    // Create maps and mutex for thread-safe access
    var mu sync.Mutex
    packetCount := make(map[string]int) // Protocol count
    uniqueIPs := make(map[string]int)    // Unique IP count

    go displayAnalysis(&mu, packetCount, uniqueIPs) // Start displaying analysis
    go startServer(&mu, packetCount, uniqueIPs)     // Start the API server

    for packet := range packetSource.Packets() {
        processPacket(&mu, packet, packetCount, uniqueIPs) // Process each packet
    }
}