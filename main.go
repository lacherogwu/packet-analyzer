package main

import (
	"fmt"
	"math/rand"
)

type PacketAnalyzer struct {
	TotalPackets      int
	AcceptedPackets   int
	RejectedPackets   int
	SuspiciousPackets int
}

func (pa *PacketAnalyzer) analyze(p Packet) PacketStatus {
	pa.TotalPackets++

	if p.Protocol == HTTP {
		pa.SuspiciousPackets++
		return SUSPICIOUS
	}

	if p.Size > 1500 {
		pa.RejectedPackets++
		return REJECTED
	}

	pa.AcceptedPackets++
	return ACCEPTED
}

type Protocol string

const (
	TCP   Protocol = "TCP"
	UDP   Protocol = "UDP"
	HTTP  Protocol = "HTTP"
	HTTPS Protocol = "HTTPS"
)

type PacketStatus int

const (
	ACCEPTED PacketStatus = iota
	REJECTED
	SUSPICIOUS
)

func (ps PacketStatus) String() string {
	return [...]string{"Accepted", "Rejecetd", "Suspicious"}[ps]
}

type Packet struct {
	Id       string
	SrcIp    string
	DestIp   string
	Protocol Protocol
	Size     int
}

func generatePacket() Packet {
	protocols := [...]Protocol{TCP, UDP, HTTP, HTTPS}
	return Packet{
		Id:       fmt.Sprintf("%d%d%d%d", rand.Intn(10), rand.Intn(10), rand.Intn(10), rand.Intn(10)),
		SrcIp:    fmt.Sprintf("%d.%d.%d.%d", rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256)),
		DestIp:   fmt.Sprintf("%d.%d.%d.%d", rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256)),
		Protocol: protocols[rand.Intn(len(protocols))],
		Size:     rand.Intn(1001) + 1000,
	}
}

func main() {

	analyzer := PacketAnalyzer{}

	for i := 0; i < 100; i++ {
		p := generatePacket()
		status := analyzer.analyze(p)
		fmt.Printf("Packet: #%s, Source IP: %s, Dest IP: %s, Protocol: %s, Size: %d bytes, Status: %s\n", p.Id, p.SrcIp, p.DestIp, p.Protocol, p.Size, status)
	}

	fmt.Printf("\nSummary:\n")
	fmt.Printf("Total Packets: %d\n", analyzer.TotalPackets)
	fmt.Printf("Accepted Packets: %d\n", analyzer.AcceptedPackets)
	fmt.Printf("Rejected Packets: %d\n", analyzer.RejectedPackets)
	fmt.Printf("Suspicious Packets: %d\n", analyzer.SuspiciousPackets)
}
