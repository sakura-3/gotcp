package tcp

import (
	"context"
	"gotcp/internal"
	"gotcp/internal/transport"
)

type Connections struct {
	pool  map[Quad]*connection
	upC   <-chan transport.Segment // ip -> tcp
	downC chan<- transport.Segment // tcp -> ip
}

func NewConnections(ctx context.Context) *Connections {
	upC, downC := internal.NewIpReader(context.WithValue(ctx, "Layer", "ip"), "gotcp", TCPFilter)

	var connections = &Connections{
		pool:  make(map[Quad]*connection),
		upC:   upC,
		downC: downC,
	}
	return connections
}
