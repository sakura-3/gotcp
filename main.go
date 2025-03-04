package main

import (
	"context"
	"gotcp/internal"
	"gotcp/internal/ip"
	"gotcp/internal/transport"
	"gotcp/internal/transport/tcp"
	"log"
)

func main() {
	upC := make(chan transport.Segment)
	downC := make(chan transport.Segment)

	ipReader := internal.NewIpReader("gotcp", upC, downC).WithFilter(func(ipPkt *ip.IPPacket) bool {
		return ipPkt.Proto == transport.IPProtoTCP
	})

	go ipReader.Run(context.Background())

	for seg := range upC {
		ts, err := tcp.NewTCPSegmentFromLower(seg)
		if err != nil {
			log.Printf("%s", err.Error())
			continue
		}

		log.Print(ts)
	}
}
