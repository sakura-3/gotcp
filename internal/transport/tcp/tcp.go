package tcp

import (
	"context"
	"gotcp/internal/datasource"
	"gotcp/internal/transport"
)

// RFC793 section 3.2
// https://datatracker.ietf.org/doc/html/rfc793#section-3.2
type SendSeqSpace struct {
	una uint32 // send unacknowledged
	nxt uint32 // send next
	wnd uint32 // send window
	up  uint32 // send urgent pointer
	wl1 uint32 // segment sequence number used for last window update
	wl2 uint32 // segment acknowledgment number used for last window
	iss uint32 // initial send sequence number
}

type RecvSeqSpace struct {
	nxt uint32 // receive next
	wnd uint32 // receive window
	up  uint32 // receive urgent pointer
	irs uint32 // initial receive sequence number
}

type connection struct {
	Quad
	State
	SendSeqSpace
	RecvSeqSpace

	MSS  int              // 最大报文段长度,RFC793中定义为uint16，本项目中约定取值为负数时代表不限制
	inC  chan *TCPSegment // Connections根据TCP报文的Quad获取connection,并通过inC将报文转交给对应的connection
	outC chan *TCPSegment // connection将报文发送给Connections,所有connection共用一个outC
}

type Connections struct {
	pool  map[Quad]*connection
	upC   <-chan *transport.Segment // ip -> tcp
	downC chan<- *transport.Segment // tcp -> ip

	outC chan *TCPSegment // pool 中所有connection共用的channel
}

func NewConnections(ctx context.Context) *Connections {
	upC, downC := datasource.NewIpReader(context.WithValue(ctx, "Layer", "ip"), "gotcp", TCPFilter)

	var connections = &Connections{
		pool:  make(map[Quad]*connection),
		upC:   upC,
		downC: downC,

		outC: make(chan *TCPSegment),
	}
	return connections
}

func (c *Connections) Run() {
	for {
		select {

		// 收到下层报文，转交给对应的connection
		case pkt := <-c.upC:
			seg, err := NewTCPSegmentFromLower(pkt)
			if err != nil {
				continue
			}
			_, ok := c.pool[seg.Quad()]
			if !ok {
				c.pool[seg.Quad()] = &connection{
					Quad: seg.Quad(),
					// TODO: 初始化状态，需要考虑connection的状态机

					inC:  make(chan *TCPSegment),
					outC: c.outC,
				}
			}
			conn := c.pool[seg.Quad()]
			conn.inC <- seg

		// 收到connection的报文，发送给ip层
		case seg := <-c.outC:
			c.downC <- &transport.Segment{
				SrcIp: seg.SrcIp,
				DstIp: seg.DstIp,
				Data:  seg.Byte(),
			}
		}
	}
}
