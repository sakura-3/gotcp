package tcp

import (
	"context"
	"gotcp/internal"
	"gotcp/internal/transport"
)

type Connections struct {
	*internal.IpReader

	pool  map[Quad]*connection
	upC   <-chan transport.Segment // ip -> tcp
	downC chan<- transport.Segment // tcp -> ip
}

func NewConnections(ctx context.Context) *Connections {
	upC := make(chan transport.Segment)
	downC := make(chan transport.Segment)

	ipReader := internal.NewIpReader("gotcp", upC, downC).WithFilter(TCPFilter)

	go ipReader.Run(context.WithValue(ctx, "layer", "ip"))

	var connections = &Connections{
		pool:     make(map[Quad]*connection),
		upC:      upC,
		downC:    downC,
		IpReader: ipReader,
	}
	return connections
}
