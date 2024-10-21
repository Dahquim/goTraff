// parser/packet_parser.go
package parser

import (
    "net"
    "time"
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
)

// PacketInfo holds details about a captured network packet
type PacketInfo struct {
    Timestamp      time.Time
    SourceIP       net.IP
    DestinationIP  net.IP
    SourcePort     int
    DestinationPort int
    Protocol       string
    Length         int
}

// ParsePacket extracts and returns packet information
func ParsePacket(packet gopacket.Packet) *PacketInfo {
    // Get timestamp
    timestamp := packet.Metadata().Timestamp

	// Extract IP Layer
    if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
        ip, _ := ipLayer.(*layers.IPv4)

        packetInfo := &PacketInfo{
            Timestamp:     timestamp,
            SourceIP:      ip.SrcIP,
            DestinationIP: ip.DstIP,
            Length:        int(ip.Length),
        }

        // Extract TCP Layer (if it exists)
        if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
            tcp, _ := tcpLayer.(*layers.TCP)
            packetInfo.SourcePort = int(tcp.SrcPort)
            packetInfo.DestinationPort = int(tcp.DstPort)
            packetInfo.Protocol = "TCP"
        }

        // Extract UDP Layer (if it exists)
        if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
            udp, _ := udpLayer.(*layers.UDP)
            packetInfo.SourcePort = int(udp.SrcPort)
            packetInfo.DestinationPort = int(udp.DstPort)
            packetInfo.Protocol = "UDP"
        }

        // Return the parsed packet
        return packetInfo
    }

    return nil
}
