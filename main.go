package main

import (
	"context"
	"gotcp/internal"
	"gotcp/internal/transport/tcp"
	"log"
)

func main() {
	upC, _ := internal.NewIpReader(context.Background(), "utun4", tcp.TCPFilter)

	for seg := range upC {
		ts, err := tcp.NewTCPSegmentFromLower(seg)
		if err != nil {
			log.Printf("%s", err.Error())
			continue
		}

		log.Print(ts)
	}
}
